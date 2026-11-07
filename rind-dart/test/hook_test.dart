// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:test/test.dart';

import '../hook/build.dart' as hook;

void main() {
  test('builds for the host, listing its sources', () async {
    await testCodeBuildHook(
      mainMethod: hook.main,
      check: (input, output) {
        expect(output.assets.code.single.file, isNotNull);
        expect(
          output.dependencies,
          containsAll([
            input.packageRoot.resolve('src/lib.rs'),
            isA<Uri>().having(
              (uri) => uri.path,
              'path',
              endsWith('/Cargo.lock'),
            ),
          ]),
        );
      },
    );
  });

  final refused = {
    'Android on ia32': (OS.android, Architecture.ia32),
    'Linux on riscv64': (OS.linux, Architecture.riscv64),
    'Fuchsia': (OS.fuchsia, Architecture.arm64),
  };
  refused.forEach((name, target) {
    test('refuses $name', () async {
      await expectLater(
        testCodeBuildHook(
          mainMethod: hook.main,
          targetOS: target.$1,
          targetArchitecture: target.$2,
          check: (_, _) {},
        ),
        throwsUnsupportedError,
      );
    });
  });

  test('refuses static linking', () async {
    await expectLater(
      testCodeBuildHook(
        mainMethod: hook.main,
        linkModePreference: LinkModePreference.static,
        check: (_, _) {},
      ),
      throwsUnsupportedError,
    );
  });

  // Cross builds, which need each target's Rust standard library and, for
  // Android, the NDK; CI's build workflow sets these.
  final targets = Platform.environment['RIND_DART_CROSS_TARGETS'];
  final ndk = Platform.environment['ANDROID_NDK_HOME'];
  for (final target in targets?.split(',') ?? const <String>[]) {
    final [os, arch, ...sdk] = target.split('-');
    test('builds for $target', () async {
      final targetOS = OS.fromString(os);
      await testCodeBuildHook(
        mainMethod: hook.main,
        targetOS: targetOS,
        targetArchitecture: Architecture.fromString(arch),
        targetIOSSdk: sdk.isEmpty
            ? IOSSdk.iPhoneOS
            : IOSSdk.fromString(sdk.single),
        targetAndroidNdkApi: 21,
        cCompiler: targetOS == OS.android ? _ndkClang(ndk!) : null,
        // testCodeBuildHook checks the library's architecture.
        check: (input, output) {},
      );
    });
  }
}

CCompilerConfig _ndkClang(String ndk) {
  final host = Platform.isMacOS ? 'darwin-x86_64' : 'linux-x86_64';
  final bin = Uri.directory('$ndk/toolchains/llvm/prebuilt/$host/bin');
  return CCompilerConfig(
    compiler: bin.resolve('clang'),
    linker: bin.resolve('ld.lld'),
    archiver: bin.resolve('llvm-ar'),
  );
}
