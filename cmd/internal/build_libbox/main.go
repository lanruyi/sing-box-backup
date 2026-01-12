package main

import (
	"archive/zip"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	_ "github.com/sagernet/gomobile"
	"github.com/sagernet/sing-box/cmd/internal/build_shared"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/rw"
	"github.com/sagernet/sing/common/shell"
)

var (
	debugEnabled      bool
	target            string
	platform          string
	withTailscale     bool
	csharpNamespace   string
	csharpPackageName string
	buildVersion      string
)

func init() {
	flag.BoolVar(&debugEnabled, "debug", false, "enable debug")
	flag.StringVar(&target, "target", "android", "target platform")
	flag.StringVar(&platform, "platform", "", "specify platform")
	flag.BoolVar(&withTailscale, "with-tailscale", false, "build tailscale for iOS and tvOS")
	flag.StringVar(&csharpNamespace, "csharp-namespace", "SagerNet", "specify C# namespace for windows")
	flag.StringVar(&csharpPackageName, "csharp-package-name", "Libbox", "specify C# package class name for windows")
}

func main() {
	flag.Parse()

	build_shared.FindMobile()

	switch target {
	case "android":
		buildAndroid()
	case "apple":
		buildApple()
	case "windows":
		buildWindows()
	default:
		log.Fatal("unsupported target: ", target)
	}
}

var (
	sharedFlags []string
	debugFlags  []string
	sharedTags  []string
	darwinTags  []string
	memcTags    []string
	notMemcTags []string
	debugTags   []string
)

func init() {
	sharedFlags = append(sharedFlags, "-trimpath")
	sharedFlags = append(sharedFlags, "-buildvcs=false")
	currentTag, err := build_shared.ReadTag()
	if err != nil {
		currentTag = "unknown"
	}
	buildVersion = currentTag
	sharedFlags = append(sharedFlags, "-ldflags", "-X github.com/sagernet/sing-box/constant.Version="+currentTag+" -X internal/godebug.defaultGODEBUG=multipathtcp=0 -s -w -buildid=  -checklinkname=0")
	debugFlags = append(debugFlags, "-ldflags", "-X github.com/sagernet/sing-box/constant.Version="+currentTag+" -X internal/godebug.defaultGODEBUG=multipathtcp=0 -checklinkname=0")

	sharedTags = append(sharedTags, "with_gvisor", "with_quic", "with_wireguard", "with_utls", "with_naive_outbound", "with_clash_api", "with_conntrack", "badlinkname", "tfogo_checklinkname0")
	darwinTags = append(darwinTags, "with_dhcp")
	memcTags = append(memcTags, "with_tailscale")
	notMemcTags = append(notMemcTags, "with_low_memory")
	debugTags = append(debugTags, "debug")
}

type AndroidBuildConfig struct {
	AndroidAPI int
	OutputName string
	Tags       []string
}

func filterTags(tags []string, exclude ...string) []string {
	excludeMap := make(map[string]bool)
	for _, tag := range exclude {
		excludeMap[tag] = true
	}
	var result []string
	for _, tag := range tags {
		if !excludeMap[tag] {
			result = append(result, tag)
		}
	}
	return result
}

func checkJavaVersion() {
	var javaPath string
	javaHome := os.Getenv("JAVA_HOME")
	if javaHome == "" {
		javaPath = "java"
	} else {
		javaPath = filepath.Join(javaHome, "bin", "java")
	}

	javaVersion, err := shell.Exec(javaPath, "--version").ReadOutput()
	if err != nil {
		log.Fatal(E.Cause(err, "check java version"))
	}
	if !strings.Contains(javaVersion, "openjdk 17") {
		log.Fatal("java version should be openjdk 17")
	}
}

func getAndroidBindTarget() string {
	if platform != "" {
		return platform
	} else if debugEnabled {
		return "android/arm64"
	}
	return "android"
}

func getWindowsBindTargets() []string {
	if platform == "" {
		return []string{"windows/386", "windows/amd64", "windows/arm64"}
	}
	var targets []string
	for _, entry := range strings.Split(platform, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		targets = append(targets, entry)
	}
	return targets
}

func buildAndroidVariant(config AndroidBuildConfig, bindTarget string) {
	args := []string{
		"bind",
		"-v",
		"-o", config.OutputName,
		"-target", bindTarget,
		"-androidapi", strconv.Itoa(config.AndroidAPI),
		"-javapkg=io.nekohasekai",
		"-libname=box",
	}

	if !debugEnabled {
		args = append(args, sharedFlags...)
	} else {
		args = append(args, debugFlags...)
	}

	args = append(args, "-tags", strings.Join(config.Tags, ","))
	args = append(args, "./experimental/libbox")

	command := exec.Command(build_shared.GoBinPath+"/gomobile", args...)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	err := command.Run()
	if err != nil {
		log.Fatal(err)
	}

	copyPath := filepath.Join("..", "sing-box-for-android", "app", "libs")
	if rw.IsDir(copyPath) {
		copyPath, _ = filepath.Abs(copyPath)
		err = rw.CopyFile(config.OutputName, filepath.Join(copyPath, config.OutputName))
		if err != nil {
			log.Fatal(err)
		}
		log.Info("copied ", config.OutputName, " to ", copyPath)
	}
}

func buildAndroid() {
	build_shared.FindSDK()
	checkJavaVersion()

	bindTarget := getAndroidBindTarget()

	// Build main variant (SDK 23)
	mainTags := append([]string{}, sharedTags...)
	mainTags = append(mainTags, memcTags...)
	if debugEnabled {
		mainTags = append(mainTags, debugTags...)
	}
	buildAndroidVariant(AndroidBuildConfig{
		AndroidAPI: 23,
		OutputName: "libbox.aar",
		Tags:       mainTags,
	}, bindTarget)

	// Build legacy variant (SDK 21, no naive outbound)
	legacyTags := filterTags(sharedTags, "with_naive_outbound")
	legacyTags = append(legacyTags, memcTags...)
	if debugEnabled {
		legacyTags = append(legacyTags, debugTags...)
	}
	buildAndroidVariant(AndroidBuildConfig{
		AndroidAPI: 21,
		OutputName: "libbox-legacy.aar",
		Tags:       legacyTags,
	}, bindTarget)
}

func buildApple() {
	var bindTarget string
	if platform != "" {
		bindTarget = platform
	} else if debugEnabled {
		bindTarget = "ios"
	} else {
		bindTarget = "ios,iossimulator,tvos,tvossimulator,macos"
	}

	args := []string{
		"bind",
		"-v",
		"-target", bindTarget,
		"-libname=box",
		"-tags-not-macos=with_low_memory",
	}
	if !withTailscale {
		args = append(args, "-tags-macos="+strings.Join(memcTags, ","))
	}

	if !debugEnabled {
		args = append(args, sharedFlags...)
	} else {
		args = append(args, debugFlags...)
	}

	tags := append(sharedTags, darwinTags...)
	if withTailscale {
		tags = append(tags, memcTags...)
	}
	if debugEnabled {
		tags = append(tags, debugTags...)
	}

	args = append(args, "-tags", strings.Join(tags, ","))
	args = append(args, "./experimental/libbox")

	command := exec.Command(build_shared.GoBinPath+"/gomobile", args...)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	err := command.Run()
	if err != nil {
		log.Fatal(err)
	}

	copyPath := filepath.Join("..", "sing-box-for-apple")
	if rw.IsDir(copyPath) {
		targetDir := filepath.Join(copyPath, "Libbox.xcframework")
		targetDir, _ = filepath.Abs(targetDir)
		os.RemoveAll(targetDir)
		os.Rename("Libbox.xcframework", targetDir)
		log.Info("copied to ", targetDir)
	}
}

func buildWindows() {
	targets := getWindowsBindTargets()
	if len(targets) == 0 {
		log.Fatal("no windows targets specified")
	}

	outputRoot := filepath.Join("build", "windows")
	configs, err := windowsBuildConfigs(targets, outputRoot)
	if err != nil {
		log.Fatal(err)
	}

	var csharpSourcePath string
	for _, config := range configs {
		args := []string{
			"bind",
			"-v",
			"-o", config.OutputName,
			"-target", config.Target,
			"-libname=box",
		}
		if csharpNamespace != "" {
			args = append(args, "-csnamespace="+csharpNamespace)
		}
		if csharpPackageName != "" {
			args = append(args, "-cspkgname="+csharpPackageName)
		}

		if !debugEnabled {
			args = append(args, sharedFlags...)
		} else {
			args = append(args, debugFlags...)
		}

		tags := filterTags(sharedTags, "with_naive_outbound")
		if debugEnabled {
			tags = append(tags, debugTags...)
		}
		args = append(args, "-tags", strings.Join(tags, ","))
		args = append(args, "./experimental/libbox")

		command := exec.Command(build_shared.GoBinPath+"/gomobile", args...)
		command.Env = append(os.Environ(), "CC="+config.CCompiler, "CXX="+config.CxxCompiler)
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
		err = command.Run()
		if err != nil {
			log.Fatal(err)
		}
		if csharpSourcePath == "" {
			csharpSourcePath = strings.TrimSuffix(config.OutputName, ".dll") + "-csharp"
		}
	}

	if csharpSourcePath == "" {
		log.Fatal("missing C# binding output")
	}

	packagePath, err := createNugetPackage(outputRoot, configs, csharpSourcePath)
	if err != nil {
		log.Fatal(err)
	}
	log.Info("created ", packagePath)
}

type WindowsBuildConfig struct {
	Architecture      string
	Target            string
	RuntimeIdentifier string
	OutputName        string
	CCompiler         string
	CxxCompiler       string
}

func windowsBuildConfigs(targets []string, outputRoot string) ([]WindowsBuildConfig, error) {
	configs := make([]WindowsBuildConfig, 0, len(targets))
	for _, target := range targets {
		config, err := windowsBuildConfig(target, outputRoot)
		if err != nil {
			return nil, err
		}
		configs = append(configs, config)
	}
	return configs, nil
}

func windowsBuildConfig(target string, outputRoot string) (WindowsBuildConfig, error) {
	parts := strings.SplitN(target, "/", 2)
	if len(parts) != 2 || parts[0] != "windows" {
		return WindowsBuildConfig{}, fmt.Errorf("invalid windows target: %s", target)
	}
	arch := parts[1]
	runtimeIdentifier, err := windowsRuntimeIdentifier(arch)
	if err != nil {
		return WindowsBuildConfig{}, err
	}
	cCompiler, cxxCompiler, err := mingwCompilers(arch)
	if err != nil {
		return WindowsBuildConfig{}, err
	}
	outputRootPath, err := filepath.Abs(outputRoot)
	if err != nil {
		return WindowsBuildConfig{}, err
	}
	outputName := filepath.Join(outputRootPath, arch, "box.dll")
	return WindowsBuildConfig{
		Architecture:      arch,
		Target:            target,
		RuntimeIdentifier: runtimeIdentifier,
		OutputName:        outputName,
		CCompiler:         cCompiler,
		CxxCompiler:       cxxCompiler,
	}, nil
}

func windowsRuntimeIdentifier(arch string) (string, error) {
	switch arch {
	case "386":
		return "win-x86", nil
	case "amd64":
		return "win-x64", nil
	case "arm64":
		return "win-arm64", nil
	default:
		return "", fmt.Errorf("unsupported windows architecture: %s", arch)
	}
}

func mingwCompilers(arch string) (string, string, error) {
	var cCompilerName string
	var cxxCompilerName string
	var cxxCompiler string
	switch arch {
	case "386":
		cCompilerName = "i686-w64-mingw32-gcc"
		cxxCompilerName = "i686-w64-mingw32-g++"
	case "amd64":
		cCompilerName = "x86_64-w64-mingw32-gcc"
		cxxCompilerName = "x86_64-w64-mingw32-g++"
	case "arm64":
		cCompilerName = "aarch64-w64-mingw32-gcc"
		cxxCompilerName = "aarch64-w64-mingw32-g++"
	default:
		return "", "", fmt.Errorf("unsupported windows architecture: %s", arch)
	}

	cCompiler, err := resolveMingwCompiler("CC", arch, cCompilerName)
	if err != nil && arch == "arm64" {
		cCompiler, cxxCompiler, err = zigCompilers(arch)
		if err == nil {
			return cCompiler, cxxCompiler, nil
		}
		return "", "", err
	}
	if err != nil {
		return "", "", err
	}
	cxxCompiler, err = resolveMingwCompiler("CXX", arch, cxxCompilerName)
	if err != nil {
		return "", "", err
	}
	return cCompiler, cxxCompiler, nil
}

func resolveMingwCompiler(kind string, arch string, fallback string) (string, error) {
	envKey := "MINGW_" + kind + "_" + strings.ToUpper(arch)
	compiler := os.Getenv(envKey)
	if compiler == "" {
		compiler = fallback
	}
	fields := strings.Fields(compiler)
	if len(fields) == 0 {
		return "", fmt.Errorf("missing mingw compiler for %s (empty %s)", arch, envKey)
	}
	compilerPath, err := exec.LookPath(fields[0])
	if err != nil {
		return "", fmt.Errorf("missing mingw compiler for %s (%s); set %s or install mingw-w64: %w", arch, compiler, envKey, err)
	}
	if len(fields) > 1 {
		return compiler, nil
	}
	return compilerPath, nil
}

func zigCompilers(arch string) (string, string, error) {
	if arch != "arm64" {
		return "", "", fmt.Errorf("unsupported zig target for %s", arch)
	}
	zigPath, err := exec.LookPath("zig")
	if err != nil {
		return "", "", err
	}
	target := "aarch64-windows-gnu"
	return fmt.Sprintf("%s cc -target %s", zigPath, target), fmt.Sprintf("%s c++ -target %s", zigPath, target), nil
}

func createNugetPackage(outputRoot string, configs []WindowsBuildConfig, csharpSourcePath string) (string, error) {
	packageRoot := filepath.Join(outputRoot, "nuget")
	err := os.RemoveAll(packageRoot)
	if err != nil {
		return "", err
	}
	err = os.MkdirAll(packageRoot, 0o755)
	if err != nil {
		return "", err
	}

	packageVersion := nugetVersion()
	nuspecPath := filepath.Join(packageRoot, "libbox.nuspec")
	err = writeNugetSpec(nuspecPath, packageVersion)
	if err != nil {
		return "", err
	}

	for _, config := range configs {
		runtimeDirectory := filepath.Join(packageRoot, "runtimes", config.RuntimeIdentifier, "native")
		err = os.MkdirAll(runtimeDirectory, 0o755)
		if err != nil {
			return "", err
		}
		err = rw.CopyFile(config.OutputName, filepath.Join(runtimeDirectory, "box.dll"))
		if err != nil {
			return "", err
		}
		headerPath := strings.TrimSuffix(config.OutputName, ".dll") + ".h"
		if rw.IsFile(headerPath) {
			err = rw.CopyFile(headerPath, filepath.Join(runtimeDirectory, "box.h"))
			if err != nil {
				return "", err
			}
		}
	}

	contentDirectory := filepath.Join(packageRoot, "contentFiles", "cs", "any", "Go")
	err = copyDirectory(csharpSourcePath, contentDirectory)
	if err != nil {
		return "", err
	}

	packageName := "Libbox.nupkg"
	packagePath := filepath.Join(".", packageName)
	err = zipDirectory(packageRoot, packagePath)
	if err != nil {
		return "", err
	}
	return packagePath, nil
}

func nugetVersion() string {
	version := strings.TrimPrefix(buildVersion, "v")
	if version == "" || version == "unknown" {
		return "0.0.0"
	}
	return version
}

func writeNugetSpec(path string, version string) error {
	content := fmt.Sprintf(`<?xml version="1.0"?>
<package>
  <metadata>
    <id>SingBox.Libbox</id>
    <version>%s</version>
    <authors>sing-box</authors>
    <description>sing-box libbox native library with C# bindings.</description>
    <requireLicenseAcceptance>false</requireLicenseAcceptance>
    <contentFiles>
      <files include="contentFiles\cs\any\Go\**\*.cs" buildAction="Compile" />
    </contentFiles>
  </metadata>
</package>
`, version)
	return os.WriteFile(path, []byte(content), 0o644)
}

func copyDirectory(sourceDirectory string, destinationDirectory string) error {
	return filepath.WalkDir(sourceDirectory, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relativePath, err := filepath.Rel(sourceDirectory, path)
		if err != nil {
			return err
		}
		targetPath := filepath.Join(destinationDirectory, relativePath)
		if entry.IsDir() {
			return os.MkdirAll(targetPath, 0o755)
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		return rw.CopyFile(path, targetPath)
	})
}

func zipDirectory(sourceDirectory string, outputPath string) error {
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	zipWriter := zip.NewWriter(outputFile)
	err = filepath.WalkDir(sourceDirectory, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		relativePath, err := filepath.Rel(sourceDirectory, path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = filepath.ToSlash(relativePath)
		header.Method = zip.Deflate
		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			return err
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		_, err = io.Copy(writer, file)
		closeErr := file.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		return nil
	})
	closeErr := zipWriter.Close()
	outputCloseErr := outputFile.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if outputCloseErr != nil {
		return outputCloseErr
	}
	return nil
}
