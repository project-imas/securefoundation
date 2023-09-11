// swift-tools-version:5.3

import PackageDescription

let package = Package(
    name: "SecureFoundation",
    platforms: [
        .iOS(.v11),
    ],
    products: [
        .library(
            name: "SecureFoundation",
            targets: ["SecureFoundation"]),
    ],
    targets: [
        .target(
            name: "SecureFoundation",
            path: "SecureFoundation",
            publicHeadersPath: ".",
            linkerSettings: [
                .linkedFramework("Security"),
            ]),
    ])