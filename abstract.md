# Abstract: Comprehensive Secure Password Vault with Distributed Recovery

## 1. Introduction
With the exponential growth of online services, users are burdened with managing numerous credentials, often leading to poor security practices such as password reuse. While specialized password managers provide a centralized repository to alleviate this burden, they must be engineered to withstand rigorous attack vectors—ranging from network sniffing and brute-force attempts to memory scraping. Furthermore, they must balance absolute security with accessibility, ensuring users are never permanently locked out of their data. This project develops a comprehensively secured, locally hosted web-based Password Manager that integrates robust cryptographic storage, active threat mitigation, secure credential generation, and a distributed master key recovery mechanism.

## 2. Problem Identification
Traditional centralized password managers often exhibit significant operational and architectural vulnerabilities:
*   **Brute-Force Susceptibility:** Without active rate-limiting and connection delays, centralized login systems are highly prone to automated dictionary or brute-force attacks.
*   **Session and Memory Vulnerabilities:** If a decrypted vault remains in system memory (RAM) indefinitely or the user walks away from their machine, malicious actors can easily hijack the active session.
*   **Poor Password Hygiene:** Access to a vault without built-in, secure password generation tools does nothing to stop users from storing easily guessable passwords.
*   **The "All-or-Nothing" Recovery Problem:** If the master encryption key is lost, the entire vault is rendered permanently inaccessible. Conversely, providing a plaintext backup key or storing it in a single central location (like email) creates a massive single point of failure.

## 3. Problem Statement
How can an organization design a holistic, fully-featured secure credential vault that provides robust session management, actively defends against brute-force and network interception, seamlessly generates highly entropic passwords, and successfully solves the master key recovery problem without introducing single points of failure in the backup infrastructure?

## 4. Proposed Solution & Feature Specification
This project builds a resilient, multi-layered Python/Flask password management system that structurally solves these problems through a unified set of features:

1.  **Strong Cryptographic Vault Engine:** All credentials are encrypted in a localized database (`vault.json`) utilizing high-grade AES-256 encryption. The system strictly governs vault access utilizing an Argon2id key derivation function, guaranteeing cryptographic strength when unwrapping the vault.
2.  **Brute-Force Mitigations & Network Security:** The application structurally slows down automated guessing attacks by implementing IP-based attack tracking and timed security delays on the login interface. Additionally, all traffic communicates strictly over a custom HTTPS/TLS self-signed wrapper to prevent malicious local packet sniffing.
3.  **Strict Session Management & Explicit RAM Wiping:** To defend against unauthorized local access, the vault maps user activity and mathematically enforces a strict 5-minute inactivity timeout. Upon timeout or manual logout, the decrypted AES key is explicitly wiped from system memory (RAM).
4.  **Credential Dashboard & Secure Generation API:** The application features a dynamic dashboard for adding, viewing, and deleting passwords. It incorporates a programmatic API generator that strictly enforces the creation of highly entropic passwords (requiring a structural mix of uppercase, lowercase, numbers, and symbols) to ensure users practice strong hygiene.
5.  **Distributed Master Key Recovery via VMs:** Utilizing Shamir’s Secret Sharing (SSS), the backup system mathematically divides the active master key into $n$ distinct shares. To completely eliminate single-point backup vulnerabilities, the application brokers the distribution of these split shares strictly across a network of separate, independent Virtual Machines. The vault can automatically be recovered only if a predefined threshold ($k$) of these specific VMs is dynamically reachable.

## 5. Pros and Cons of the Proposed Work

### Pros:
*   **Comprehensive Threat Surface Mitigation:** It actively defends the user on all fronts: the network level (HTTPS), the application layer (brute force delay & auto-timeout), and cryptography (AES-256 + Argon2id).
*   **Promotes Excellent Security Hygiene:** The built-in generation APIs ensure passwords created by the user are practically unguessable.
*   **Fault-Tolerant Recovery:** The distributed Shamir/VM architecture guarantees the vault can survive hardware failures (up to $n - k$ offline VMs) while defending against a compromise of individual backup nodes.
*   **No Single Point of Failure and Zero-Knowledge:** The central server never permanently stores the key, and no single administrator possesses enough data to reconstruct it.

### Cons:
*   **High Architectural and Administrative Complexity:** Deploying this system requires not only configuring a Flask web environment but also maintaining an ecosystem of secure, interconnected separate Virtual Machines with distinct TLS configurations.
*   **Execution and Performance Overhead:** The combination of intentional active-login delays, Argon2id mathematical derivations, and network-latency checks across remote VMs when recovering shares makes the application slower than standard basic login interfaces.
*   **Strict Connectivity Dependency for Recovery:** If external network access acts up unexpectedly and the required threshold sum of VMs cannot be reached simultaneously, recovery is impossible until the network stabilizes.
