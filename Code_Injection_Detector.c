#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <curl/curl.h>
#include <regex.h>
#include <arpa/inet.h>

// Define some patterns for common code injections (SQL Injection, XSS, etc.)
const char* COMMON_ATTACK_PATTERNS[] = {
    "(select|insert|update|delete.*from|select.*union.*select)",  // SQL Injection
    "<script.*?>.*?</script.*?>",  // XSS Script Injection
    "(eval|exec|system).*",  // Code execution functions
    "(base64_decode|eval|shell_exec)",  // Base64 decode and other code injection
    "(drop.*table)",  // Drop table SQL Injection
    "(union.*select)",  // SQL Union Injection
    "(cmd.*exec)",  // Command injection
    "(--.*comment)"  // SQL comment injection
};
#define PATTERN_COUNT 7

// Function to check content against malicious patterns using regular expressions
int check_for_malicious_code(const char *content) {
    regex_t regex;
    int result;
    for (int i = 0; i < PATTERN_COUNT; i++) {
        result = regcomp(&regex, COMMON_ATTACK_PATTERNS[i], REG_ICASE);
        if (result) {
            printf("Could not compile regex\n");
            exit(1);
        }

        result = regexec(&regex, content, 0, NULL, 0);
        if (result == 0) {
            regfree(&regex);
            return 1;  // Malicious code found
        }

        regfree(&regex);
    }
    return 0;  // No malicious code found
}

// Callback function for libcurl to capture HTTP response content
size_t write_callback(void *ptr, size_t size, size_t nmemb, char *data) {
    strcat(data, ptr);
    return size * nmemb;
}

// Function to monitor a website for potential code injection attempts
void monitor_website_for_code_injection(const char* url) {
    CURL *curl;
    CURLcode res;
    char data[4096] = "";  // Buffer to store website content

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, data);

        res = curl_easy_perform(curl);

        if (res == CURLE_OK) {
            printf("Successfully connected to %s. Analyzing content...\n", url);
            if (check_for_malicious_code(data)) {
                printf("[ALERT] Potential malicious code detected!\n");
            } else {
                printf("[INFO] No suspicious code detected.\n");
            }
        } else {
            printf("Failed to access the URL %s. Error: %s\n", url, curl_easy_strerror(res));
        }

        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();
}

// Function to monitor network traffic for suspicious patterns (simulated with queries)
void monitor_network_traffic(const char* ip_address) {
    // For simulation purposes, we use some hardcoded malicious queries
    const char *sample_queries[] = {
        "SELECT * FROM users WHERE username = 'admin' --",
        "<script>alert('XSS attack');</script>",
        "DROP TABLE users;",
        "eval(base64_decode('somebase64encodedstring'))"
    };

    printf("Monitoring network traffic for IP: %s\n", ip_address);
    for (int i = 0; i < 4; i++) {
        printf("Checking query: %s\n", sample_queries[i]);
        if (check_for_malicious_code(sample_queries[i])) {
            printf("[ALERT] Potential malicious code detected!\n");
        } else {
            printf("[INFO] No suspicious code detected.\n");
        }
    }
}

// Function to start monitoring based on user input
void start_monitoring() {
    int monitor_type;
    printf("Enter the monitoring type (1 for website, 2 for network traffic): ");
    scanf("%d", &monitor_type);

    if (monitor_type == 1) {
        char url[256];
        printf("Enter the URL to monitor for potential code injections: ");
        scanf("%s", url);
        monitor_website_for_code_injection(url);
    } else if (monitor_type == 2) {
        char ip_address[16];
        printf("Enter the IP address to monitor for network traffic:");
        scanf("%s", ip_address);
        monitor_network_traffic(ip_address);
    } else {
        printf("Invalid option selected. Please choose 1 for website or 2 for network traffic.\n");
    }
}

int main() {
    start_monitoring();
    return 0;
}
