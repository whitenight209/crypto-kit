# crypto-kit

PBKDF2 키 유도와 AES-256-GCM 암호화를 제공하는 스레드 안전 Java 라이브러리.  
편의 API(패스워드 기반)와 배치 처리에 최적화된 고속 API를 모두 지원합니다.

## 요구사항

- Java 17+
- Gradle 8+

## 빌드

```bash
./gradlew build
```

## GitHub Packages 배포

이 프로젝트는 GitHub Packages Maven registry로 배포할 수 있도록 설정되어 있습니다.

필요한 인증 정보:

```bash
export GITHUB_ACTOR=YOUR_GITHUB_USERNAME
export GITHUB_TOKEN=YOUR_GITHUB_PACKAGES_TOKEN
```

선택적으로 저장소 정보도 덮어쓸 수 있습니다. 보통 GitHub Actions에서는 현재 저장소 기준으로 자동 처리되므로 로컬에서 다른 owner/repo로 배포할 때만 필요합니다.

```bash
export GITHUB_OWNER=whitenight209
export GITHUB_REPOSITORY_NAME=crypto-kit
```

배포:

```bash
./gradlew publish
```

`publish`는 `mavenLocal()`과 GitHub Packages 둘 다 대상으로 동작합니다. GitHub Packages만 보낼 때는:

```bash
./gradlew publishMavenJavaPublicationToGitHubPackagesRepository
```

GitHub Actions 배포:

- `.github/workflows/publish-github-packages.yml` 이 추가되어 있습니다.
- `workflow_dispatch`로 수동 실행할 수 있습니다.
- `v*` 태그 푸시 예: `v1.0.0` 시 자동으로 GitHub Packages에 배포됩니다.
- workflow에서는 `github.actor`와 기본 `secrets.GITHUB_TOKEN`을 사용하므로 별도 PAT secret 없이 동작하는 구성이 기본입니다.

다른 프로젝트에서 사용:

먼저 로컬 환경에 GitHub Packages 읽기용 토큰을 설정합니다. GitHub 문서 기준으로 로컬 설치에는 보통 `PAT classic`의 `read:packages` 권한이 필요합니다.

```bash
export GPR_USER=YOUR_GITHUB_USERNAME
export GPR_TOKEN=YOUR_GITHUB_CLASSIC_PAT
```

```groovy
repositories {
    maven {
        url = uri("https://maven.pkg.github.com/whitenight209/crypto-kit")
        credentials {
            username = System.getenv("GPR_USER")
            password = System.getenv("GPR_TOKEN")
        }
    }
    mavenCentral()
}

dependencies {
    implementation 'com.chpark.crypto:crypto-kit:1.0.0'
}
```

Maven CLI 예시:

```xml
<repositories>
  <repository>
    <id>github</id>
    <url>https://maven.pkg.github.com/whitenight209/crypto-kit</url>
  </repository>
</repositories>
```

```xml
<dependency>
  <groupId>com.chpark.crypto</groupId>
  <artifactId>crypto-kit</artifactId>
  <version>1.0.0</version>
</dependency>
```

## 의존성 추가

로컬 jar를 빌드한 뒤 프로젝트에 추가합니다.

```bash
./gradlew jar
```

```groovy
// build.gradle
implementation files('/path/to/crypto-kit/build/libs/crypto-kit-1.0.0.jar')
```

---

## 사용법

### 1. 편의 API — 패스워드 기반 (단일 파일 암호화 등)

패스워드만으로 암호화/복호화합니다. salt와 nonce가 출력 바이트 배열에 자동으로 포함됩니다.

```java
import com.chpark.crypto.CryptoEngine;

CryptoEngine engine = new CryptoEngine();

// 암호화
byte[] plaintext  = "Hello, World!".getBytes(StandardCharsets.UTF_8);
byte[] ciphertext = engine.encrypt("my-password", plaintext);

// 복호화
byte[] decrypted  = engine.decrypt("my-password", ciphertext);
```

**출력 포맷:** `[magic header 5B][salt 16B][nonce 12B][ciphertext + GCM tag 16B]`

암호화된 데이터는 항상 `CKIT` + 버전 바이트로 시작합니다. `CryptoEngine.hasMagicHeader(bytes)`로 crypto-kit 암호화 데이터인지 확인할 수 있습니다.
기존 버전에서 생성된 헤더 없는 데이터도 복호화할 수 있습니다.

---

### 2. 고속 API — 사전 키 파생 (배치 처리)

동일한 패스워드로 여러 파일을 암호화할 때, PBKDF2를 한 번만 수행하고 키를 재사용합니다.

```java
import com.chpark.crypto.CryptoEngine;
import java.security.SecureRandom;

CryptoEngine engine = new CryptoEngine();

// 키 1회 파생
byte[] salt = new byte[16];
new SecureRandom().nextBytes(salt);
byte[] key = engine.deriveKey("my-password", salt);

// 여러 파일을 동일 키로 암호화 (PBKDF2 오버헤드 없음)
byte[] cipher1 = engine.encrypt(key, data1);
byte[] cipher2 = engine.encrypt(key, data2);

// 복호화
byte[] plain1 = engine.decrypt(key, cipher1);
```

**출력 포맷:** `[magic header 5B][nonce 12B][ciphertext + GCM tag 16B]`

---

### 3. 설정 커스터마이징

`CryptoConfig`로 iteration count, key length 등을 조정할 수 있습니다.

```java
import com.chpark.crypto.CryptoConfig;
import com.chpark.crypto.CryptoEngine;

CryptoConfig config = new CryptoConfig(
    16,       // saltLength  (bytes)
    12,       // nonceLength (bytes)
    256,      // keyLength   (bits)  — 128 / 192 / 256
    128,      // tagLength   (bits)  — 128 고정
    600_000   // iterationCount (PBKDF2)
);

CryptoEngine engine = new CryptoEngine(config);
```

기본값 (`CryptoConfig.DEFAULT`):

| 항목 | 값 |
|---|---|
| saltLength | 16 bytes |
| nonceLength | 12 bytes |
| keyLength | 256 bits |
| tagLength | 128 bits |
| iterationCount | 310,000 |

---

## 보안 설계

| 항목 | 내용 |
|---|---|
| 암호화 알고리즘 | AES-256-GCM (AEAD — 기밀성 + 무결성 동시 보장) |
| 키 유도 | PBKDF2WithHmacSHA256, 310,000 iterations (OWASP 2023 권고) |
| Salt | 암호화마다 `SecureRandom`으로 16 bytes 신규 생성 |
| Nonce | 암호화마다 `SecureRandom`으로 12 bytes 신규 생성 |
| GCM 인증 태그 | 128 bits — 복호화 시 태그 불일치 시 `CryptoException` |
| 스레드 안전성 | `ThreadLocal<GCMBlockCipher>`로 인스턴스 공유 없이 처리 |
| 키 메모리 정리 | 사용 후 `Arrays.fill(key, 0)` |
| 구현체 | Java 17 표준 JCE (`AES/GCM/NoPadding`, `PBKDF2WithHmacSHA256`) |

---

## 예외 처리

```java
import com.chpark.crypto.CryptoException;

try {
    byte[] decrypted = engine.decrypt("wrong-password", ciphertext);
} catch (CryptoException e) {
    // 패스워드 불일치 또는 데이터 변조 시 발생
    System.err.println("복호화 실패: " + e.getMessage());
}
```

---

## 라이선스

MIT
