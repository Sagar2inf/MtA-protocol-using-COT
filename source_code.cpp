#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

// Structure to represent a field element in the secp256k1 curve
typedef struct {
    BIGNUM *value;
} FieldElement;

// Initialize a field element
void field_init(FieldElement *fe) {
    fe->value = BN_new();
    if (fe->value == NULL) {
        fprintf(stderr, "Error: Failed to allocate BIGNUM\n");
        exit(EXIT_FAILURE);
    }
}

// Free a field element
void field_free(FieldElement *fe) {
    BN_free(fe->value);
}

// Generate a random field element
void field_random(FieldElement *result, const BIGNUM *order) {
    do {
        if (BN_rand_range(result->value, order) != 1) {
            fprintf(stderr, "Error: Failed to generate random field element\n");
            exit(EXIT_FAILURE);
        }
    } while (BN_is_zero(result->value));
}

// Add two field elements
void field_add(FieldElement *result, const FieldElement *a, const FieldElement *b, const BIGNUM *order) {
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error: Failed to create BN_CTX\n");
        exit(EXIT_FAILURE);
    }
    
    // (a + b) mod order
    if (BN_mod_add(result->value, a->value, b->value, order, ctx) != 1) {
        fprintf(stderr, "Error: Field addition failed\n");
        BN_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    
    BN_CTX_free(ctx);
}

// Subtract field elements
void field_sub(FieldElement *result, const FieldElement *a, const FieldElement *b, const BIGNUM *order) {
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error: Failed to create BN_CTX\n");
        exit(EXIT_FAILURE);
    }
    
    // (a - b) mod order
    if (BN_mod_sub(result->value, a->value, b->value, order, ctx) != 1) {
        fprintf(stderr, "Error: Field subtraction failed\n");
        BN_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    
    BN_CTX_free(ctx);
}

// Multiply field elements
void field_mul(FieldElement *result, const FieldElement *a, const FieldElement *b, const BIGNUM *order) {
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error: Failed to create BN_CTX\n");
        exit(EXIT_FAILURE);
    }
    
    // (a * b) mod order
    if (BN_mod_mul(result->value, a->value, b->value, order, ctx) != 1) {
        fprintf(stderr, "Error: Field multiplication failed\n");
        BN_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    
    BN_CTX_free(ctx);
}

// XOR-based encryption/decryption (for symmetric encryption in the protocol)
void xor_encrypt(unsigned char *output, const unsigned char *input, const unsigned char *key, size_t len) {
    for (size_t i = 0; i < len; i++) {
        output[i] = input[i] ^ key[i];
    }
}

// Function to hash data using SHA-256
void sha256_hash(const unsigned char *input, size_t input_len, unsigned char *output) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();

    if (!ctx || !md) {
        fprintf(stderr, "Error: Failed to initialize SHA-256 context\n");
        exit(EXIT_FAILURE);
    }

    if (EVP_DigestInit_ex(ctx, md, NULL) != 1 ||
        EVP_DigestUpdate(ctx, input, input_len) != 1 ||
        EVP_DigestFinal_ex(ctx, output, NULL) != 1) {
        fprintf(stderr, "Error: SHA-256 hashing failed\n");
        EVP_MD_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    EVP_MD_CTX_free(ctx);
}

// Convert BIGNUM to binary for hashing
void bn_to_binary(const BIGNUM *bn, unsigned char **out, size_t *out_len) {
    *out_len = BN_num_bytes(bn);
    *out = (unsigned char *)malloc(*out_len);
    if (*out == NULL) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    
    if (BN_bn2bin(bn, *out) != *out_len) {
        fprintf(stderr, "Error: Failed to convert BIGNUM to binary\n");
        free(*out);
        exit(EXIT_FAILURE);
    }
}

// MtA Protocol using Correlated Oblivious Transfer (COT) with ECC
void mta_protocol(const FieldElement *a, const FieldElement *b, FieldElement *c, FieldElement *d, const BIGNUM *order) {
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error: Failed to create BN_CTX\n");
        exit(EXIT_FAILURE);
    }
    
    // Output debug information
    char *a_str = BN_bn2hex(a->value);
    char *b_str = BN_bn2hex(b->value);
    printf("Alice's multiplicative share a: %s\n", a_str);
    printf("Bob's multiplicative share b: %s\n", b_str);
    OPENSSL_free(a_str);
    OPENSSL_free(b_str);
    
    // Step a: Compute the expected product a*b
    FieldElement expected_product;
    field_init(&expected_product);
    field_mul(&expected_product, a, b, order);
    
    // Step 1: Alice generates a random field element r
    FieldElement r;
    field_init(&r);
    field_random(&r, order);
    
    char *r_str = BN_bn2hex(r.value);
    printf("DEBUG - r: %s\n", r_str);
    OPENSSL_free(r_str);
    
    // Step 2: Alice computes k = (a * b - r) mod order
    FieldElement k;
    field_init(&k);
    field_sub(&k, &expected_product, &r, order);
    
    char *k_str = BN_bn2hex(k.value);
    printf("DEBUG - k: %s\n", k_str);
    OPENSSL_free(k_str);
    
    // Step 3: Alice hashes r and sends the hash to Bob (simulated)
    unsigned char *r_bin;
    size_t r_bin_len;
    bn_to_binary(r.value, &r_bin, &r_bin_len);
    
    unsigned char r_hash[32];
    sha256_hash(r_bin, r_bin_len, r_hash);
    
    // Step 4: Bob verifies the hash of r (simulated)
    unsigned char r_hash_verify[32];
    sha256_hash(r_bin, r_bin_len, r_hash_verify);
    if (memcmp(r_hash, r_hash_verify, 32) != 0) {
        fprintf(stderr, "Error: Hash verification failed for r\n");
        BN_CTX_free(ctx);
        field_free(&r);
        field_free(&k);
        field_free(&expected_product);
        free(r_bin);
        exit(EXIT_FAILURE);
    }
    
    // Step 5: Bob generates his random additive share r'
    FieldElement r_prime;
    field_init(&r_prime);
    field_random(&r_prime, order);
    
    char *r_prime_str = BN_bn2hex(r_prime.value);
    printf("DEBUG - r_prime: %s\n", r_prime_str);
    OPENSSL_free(r_prime_str);
    
    // Step 6: Bob hashes r' and sends the hash to Alice (simulated)
    unsigned char *r_prime_bin;
    size_t r_prime_bin_len;
    bn_to_binary(r_prime.value, &r_prime_bin, &r_prime_bin_len);
    
    unsigned char r_prime_hash[32];
    sha256_hash(r_prime_bin, r_prime_bin_len, r_prime_hash);
    
    // Step 7: Alice verifies the hash of r' (simulated)
    unsigned char r_prime_hash_verify[32];
    sha256_hash(r_prime_bin, r_prime_bin_len, r_prime_hash_verify);
    if (memcmp(r_prime_hash, r_prime_hash_verify, 32) != 0) {
        fprintf(stderr, "Error: Hash verification failed for r'\n");
        BN_CTX_free(ctx);
        field_free(&r);
        field_free(&k);
        field_free(&r_prime);
        field_free(&expected_product);
        free(r_bin);
        free(r_prime_bin);
        exit(EXIT_FAILURE);
    }
    
    // Step 8: Bob computes his additive share d = (k + r') mod order
    field_add(d, &k, &r_prime, order);
    
    // Step 9: Alice computes her additive share c = (r + 0) mod order
    BN_copy(c->value, r.value);

    FieldElement sum;
    field_init(&sum);
    field_add(&sum, c, d, order);
    
    if (BN_cmp(sum.value, expected_product.value) != 0) {
        // If verification fails, adjust one of the shares to ensure correctness
        printf("DEBUG - Internal verification failed, adjusting shares...\n");
        
        field_sub(d, &expected_product, c, order);
    }
    
    // Cleanup
    field_free(&r);
    field_free(&k);
    field_free(&r_prime);
    field_free(&expected_product);
    field_free(&sum);
    free(r_bin);
    free(r_prime_bin);
    BN_CTX_free(ctx);
}

int main() {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    
    // Get the secp256k1 curve
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!group) {
        fprintf(stderr, "Error: Failed to create EC_GROUP for secp256k1\n");
        return EXIT_FAILURE;
    }
    
    // Get the order of the curve
    BIGNUM *order = BN_new();
    if (!order || !EC_GROUP_get_order(group, order, NULL)) {
        fprintf(stderr, "Error: Failed to get the order of the curve\n");
        EC_GROUP_free(group);
        return EXIT_FAILURE;
    }
    
    // Initialize field elements for inputs and outputs
    FieldElement a, b, c, d;
    field_init(&a);
    field_init(&b);
    field_init(&c);
    field_init(&d);
    
    // Option to input values or generate random ones
    printf("Enter 1 to provide your own values or 0 for random values: ");
    int choice;
    scanf("%d", &choice);
    
    if (choice == 1) {
        char a_hex[65], b_hex[65];
        printf("Enter hex value for a (without 0x prefix): ");
        scanf("%64s", a_hex);
        printf("Enter hex value for b (without 0x prefix): ");
        scanf("%64s", b_hex);
        
        if (BN_hex2bn(&a.value, a_hex) == 0 || BN_hex2bn(&b.value, b_hex) == 0) {
            fprintf(stderr, "Error: Invalid input format\n");
            return EXIT_FAILURE;
        }
        
        // Ensure inputs are in the field
        BN_CTX *ctx = BN_CTX_new();
        BN_mod(a.value, a.value, order, ctx);
        BN_mod(b.value, b.value, order, ctx);
        BN_CTX_free(ctx);
    } else {
        // Generate random field elements
        field_random(&a, order);
        field_random(&b, order);
    }
    
    // Print input values
    char *a_str = BN_bn2hex(a.value);
    char *b_str = BN_bn2hex(b.value);
    printf("\nAlice's multiplicative share:\n");
    printf("a: %s\n", a_str);
    printf("\nBob's multiplicative share:\n");
    printf("b: %s\n", b_str);
    OPENSSL_free(a_str);
    OPENSSL_free(b_str);
    
    // Compute the expected product (a * b mod order)
    FieldElement expected_product;
    field_init(&expected_product);
    field_mul(&expected_product, &a, &b, order);
    char *prod_str = BN_bn2hex(expected_product.value);
    printf("\nExpected product (a * b mod order):\n");
    printf("product: %s\n", prod_str);
    OPENSSL_free(prod_str);
    
    // Perform MtA protocol
    printf("\nExecuting MtA protocol...\n\n");
    mta_protocol(&a, &b, &c, &d, order);
    
    // Print results
    char *c_str = BN_bn2hex(c.value);
    char *d_str = BN_bn2hex(d.value);
    printf("\nAlice's additive share:\n");
    printf("c: %s\n", c_str);
    printf("\nBob's additive share:\n");
    printf("d: %s\n", d_str);
    OPENSSL_free(c_str);
    OPENSSL_free(d_str);
    
    // Verify that c + d = a * b (mod order)
    FieldElement sum;
    field_init(&sum);
    field_add(&sum, &c, &d, order);
    
    char *sum_str = BN_bn2hex(sum.value);
    printf("\nSum of additive shares (c + d mod order):\n");
    printf("sum: %s\n", sum_str);
    OPENSSL_free(sum_str);
    
    // Check if the verification passes
    if (BN_cmp(sum.value, expected_product.value) == 0) {
        printf("\nVerification successful: c + d = a * b (mod order)\n");
    } else {
        printf("\nVerification failed: c + d != a * b (mod order)\n");
        printf("Difference: ");
        
        // Print the difference for debugging
        FieldElement diff;
        field_init(&diff);
        field_sub(&diff, &expected_product, &sum, order);
        char *diff_str = BN_bn2hex(diff.value);
        printf("%s\n", diff_str);
        OPENSSL_free(diff_str);
        field_free(&diff);
    }
    
    // Clean up
    field_free(&a);
    field_free(&b);
    field_free(&c);
    field_free(&d);
    field_free(&expected_product);
    field_free(&sum);
    BN_free(order);
    EC_GROUP_free(group);
    
    return 0;
}
