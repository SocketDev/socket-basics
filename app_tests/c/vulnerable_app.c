#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Hardcoded credentials
#define SECRET_KEY "super_secret_password_123"
#define API_TOKEN "sk-1234567890abcdef"

void buffer_overflow_vuln() {
    char buffer[64];
    char user_input[256];
    
    printf("Enter some text: ");
    gets(user_input);  // Buffer overflow vulnerability - deprecated function
    
    strcpy(buffer, user_input);  // Potential buffer overflow
    printf("You entered: %s\n", buffer);
}

void format_string_vuln() {
    char user_input[256];
    printf("Enter format string: ");
    fgets(user_input, sizeof(user_input), stdin);
    
    // Format string vulnerability
    printf(user_input);
}

void command_injection_vuln() {
    char command[512];
    char user_input[256];
    
    printf("Enter filename to list: ");
    scanf("%255s", user_input);
    
    // Command injection vulnerability
    sprintf(command, "ls -la %s", user_input);
    system(command);
}

void memory_leak() {
    // Memory leak - allocated but never freed
    char *leaked_memory = malloc(1024);
    strcpy(leaked_memory, "This memory will never be freed");
}

void use_after_free() {
    char *ptr = malloc(100);
    strcpy(ptr, "Hello World");
    free(ptr);
    
    // Use after free vulnerability
    printf("Freed memory content: %s\n", ptr);
}

int main() {
    printf("=== Vulnerable C Application ===\n");
    printf("Secret Key: %s\n", SECRET_KEY);  // Hardcoded secret exposure
    
    printf("1. Testing buffer overflow...\n");
    buffer_overflow_vuln();
    
    printf("\n2. Testing format string vulnerability...\n");
    format_string_vuln();
    
    printf("\n3. Testing command injection...\n");
    command_injection_vuln();
    
    printf("\n4. Creating memory leak...\n");
    memory_leak();
    
    printf("\n5. Testing use after free...\n");
    use_after_free();
    
    return 0;
}
