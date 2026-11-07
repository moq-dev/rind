// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// Builds the `rind-dart` crate beside this package with cargo, for the target
// the Dart or Flutter build asks for, and bundles it as this package's code
// asset. A target rind has no backend for fails here rather than at run time.

import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';

void main(List<String> args) async {
  await build(args, (input, output) async {
    if (!input.config.buildCodeAssets) return;
    final code = input.config.code;
    if (code.linkModePreference == LinkModePreference.static) {
      throw UnsupportedError('rind builds only a dynamic library');
    }

    final target = rustTarget(code);
    final manifest = input.packageRoot.resolve('Cargo.toml');
    final targetDir = input.outputDirectoryShared.resolve('target/');
    final env = <String, String>{};
    final linkArgs = <String>[];

    switch (code.targetOS) {
      case OS.android:
        // The NDK's clang links, for the app's minimum API level.
        final clang = code.cCompiler?.compiler;
        if (clang == null) {
          throw UnsupportedError('building rind for Android needs the NDK');
        }
        final api = code.android.targetNdkApi;
        final clangTarget = target.replaceFirst('armv7-', 'armv7a-');
        linkArgs
          ..add('-Clinker=${clang.toFilePath()}')
          ..add('-Clink-arg=--target=$clangTarget$api')
          // Android 15 devices may use 16 KB pages, which Google Play
          // requires apps to support.
          ..add('-Clink-arg=-Wl,-z,max-page-size=16384');
      case OS.iOS:
        final version = code.iOS.deploymentVersion;
        env['IPHONEOS_DEPLOYMENT_TARGET'] = '${version.major}.${version.minor}';
      case OS.macOS:
        final version = code.macOS.deploymentVersion;
        env['MACOSX_DEPLOYMENT_TARGET'] = '${version.major}.${version.minor}';
    }

    await _checkTargetInstalled(target);
    final cargo = await Process.run('cargo', [
      'rustc',
      '--release',
      '--locked',
      '--lib',
      '--manifest-path',
      manifest.toFilePath(),
      '--target',
      target,
      '--target-dir',
      targetDir.toFilePath(),
      if (linkArgs.isNotEmpty) ...['--', ...linkArgs],
    ], environment: env);
    if (cargo.exitCode != 0) {
      throw ProcessException(
        'cargo',
        const [],
        'building rind for $target failed:\n${cargo.stderr}',
        cargo.exitCode,
      );
    }

    final outDir = targetDir.resolve('$target/release/');
    final library = outDir.resolve(code.targetOS.dylibFileName('rind_dart'));
    output.assets.code.add(
      CodeAsset(
        package: input.packageName,
        name: 'src/bindings.dart',
        linkMode: DynamicLoadingBundled(),
        file: library,
      ),
    );

    // Cargo lists every source file the library depends on beside it.
    final depInfo = outDir.resolve(
      code.targetOS
          .dylibFileName('rind_dart')
          .replaceFirst(RegExp(r'\.[^.]+$'), '.d'),
    );
    // Its lockfile and manifest, the workspace's in this repository and the
    // package's own once published, pick the dependencies' versions.
    final workspace = await Process.run('cargo', [
      'locate-project',
      '--workspace',
      '--message-format',
      'plain',
      '--manifest-path',
      manifest.toFilePath(),
    ]);
    if (workspace.exitCode != 0) {
      throw ProcessException(
        'cargo',
        const ['locate-project'],
        '${workspace.stderr}',
        workspace.exitCode,
      );
    }
    final workspaceManifest = Uri.file((workspace.stdout as String).trim());
    output.dependencies
      ..add(manifest)
      ..add(workspaceManifest)
      ..add(workspaceManifest.resolve('Cargo.lock'))
      ..addAll(_parseDepInfo(File.fromUri(depInfo).readAsStringSync()));
  });
}

/// The Rust target triple for [code]'s target, refusing one rind lacks.
String rustTarget(CodeConfig code) {
  final arch = code.targetArchitecture;
  final os = code.targetOS;
  final triple = switch ((os, arch)) {
    (OS.android, Architecture.arm64) => 'aarch64-linux-android',
    (OS.android, Architecture.arm) => 'armv7-linux-androideabi',
    (OS.android, Architecture.x64) => 'x86_64-linux-android',
    (OS.iOS, Architecture.arm64) =>
      code.iOS.targetSdk == IOSSdk.iPhoneSimulator
          ? 'aarch64-apple-ios-sim'
          : 'aarch64-apple-ios',
    (OS.iOS, Architecture.x64) => 'x86_64-apple-ios',
    (OS.macOS, Architecture.arm64) => 'aarch64-apple-darwin',
    (OS.macOS, Architecture.x64) => 'x86_64-apple-darwin',
    (OS.linux, Architecture.arm64) => 'aarch64-unknown-linux-gnu',
    (OS.linux, Architecture.arm) => 'armv7-unknown-linux-gnueabihf',
    (OS.linux, Architecture.x64) => 'x86_64-unknown-linux-gnu',
    (OS.windows, Architecture.arm64) => 'aarch64-pc-windows-msvc',
    (OS.windows, Architecture.x64) => 'x86_64-pc-windows-msvc',
    _ => null,
  };
  if (triple == null) {
    throw UnsupportedError('rind does not support $os on $arch');
  }
  return triple;
}

/// Fails with the command that installs [target]'s standard library, which
/// cargo would otherwise report as a missing `core` crate.
Future<void> _checkTargetInstalled(String target) async {
  final ProcessResult sysroot;
  try {
    sysroot = await Process.run('rustc', ['--print', 'sysroot']);
  } on ProcessException {
    throw UnsupportedError(
      'building rind needs Rust 1.90 or later; install it from https://rustup.rs',
    );
  }
  final lib = Directory(
    '${(sysroot.stdout as String).trim()}/lib/rustlib/$target',
  );
  if (!lib.existsSync()) {
    throw UnsupportedError(
      "Rust's standard library for $target is not installed; "
      'run `rustup target add $target`',
    );
  }
}

/// The files a Makefile-style dep-info file lists, in which a backslash
/// escapes a space in a path.
Iterable<Uri> _parseDepInfo(String depInfo) sync* {
  final rule = depInfo.split('\n').first;
  final deps = rule.substring(rule.indexOf(': ') + 2);
  for (final path in deps.split(RegExp(r'(?<!\\) '))) {
    if (path.isNotEmpty) yield Uri.file(path.replaceAll(r'\ ', ' '));
  }
}
