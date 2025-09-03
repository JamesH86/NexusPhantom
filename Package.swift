// swift-tools-version: 5.9
// NEXUS PHANTOM - Elite Cybersecurity AI Platform

import PackageDescription

let package = Package(
    name: "NexusPhantom",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "NexusPhantom", targets: ["NexusPhantom"]),
        .library(name: "NexusPhantomCore", targets: ["NexusPhantomCore"])
    ],
    dependencies: [
        // gRPC for AI model communication
        .package(url: "https://github.com/grpc/grpc-swift.git", from: "1.21.0"),
        
        // Cryptography for secure operations
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
        
        // Logging framework
        .package(url: "https://github.com/apple/swift-log.git", from: "1.0.0"),
        
        // Command line argument parsing
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.0.0"),
        
        // Redis for real-time data streaming
        .package(url: "https://github.com/vapor/redis.git", from: "4.0.0"),
        
        // HTTP client for API integrations
        .package(url: "https://github.com/swift-server/async-http-client.git", from: "1.9.0"),
        
        // JSON Web Tokens for authentication
        .package(url: "https://github.com/vapor/jwt.git", from: "4.0.0"),
        
        // WebSocket support for real-time communication
        .package(url: "https://github.com/vapor/websocket-kit.git", from: "2.0.0"),
        
        // SQLite for local data storage
        .package(url: "https://github.com/stephencelis/SQLite.swift.git", from: "0.14.1")
    ],
    targets: [
        .executableTarget(
            name: "NexusPhantom",
            dependencies: [
                "NexusPhantomCore",
                .product(name: "GRPC", package: "grpc-swift"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "AsyncHTTPClient", package: "async-http-client")
            ],
            path: "Sources/NexusPhantom",
            resources: [
                .copy("install_tools.sh")
            ]
        ),
        
        .target(
            name: "NexusPhantomCore",
            dependencies: [
                .product(name: "GRPC", package: "grpc-swift"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "Redis", package: "redis"),
                .product(name: "JWT", package: "jwt"),
                .product(name: "WebSocketKit", package: "websocket-kit"),
                .product(name: "SQLite", package: "SQLite.swift")
            ],
        ),
        
        .testTarget(
            name: "NexusPhantomTests",
            dependencies: [
                "NexusPhantom", 
                "NexusPhantomCore"
            ]
        ),
        
        .testTarget(
            name: "NexusPhantomCoreTests",
            dependencies: [
                "NexusPhantomCore"
            ]
        )
    ]
)
