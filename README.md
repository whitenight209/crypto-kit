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

## 의존성 추가

로컬 jar를 빌드한 뒤 프로젝트에 추가합니다.

```bash
./gradlew jar
```

```groovy
// build.gradle
implementation files('/path/to/crypto-kit/build/libs/crypto-kit-1.0.0.jar')
implementation 'org.bouncycastle:bcprov-jdk18on:1.78.1'
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

**출력 포맷:** `[salt 16B][nonce 12B][ciphertext + GCM tag 16B]`

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

**출력 포맷:** `[nonce 12B][ciphertext + GCM tag 16B]`

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
| 구현체 | Bouncy Castle (`bcprov-jdk18on`) |

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
