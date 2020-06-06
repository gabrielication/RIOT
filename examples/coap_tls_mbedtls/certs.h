#if defined(MBEDTLS_X509_CRT_PARSE_C)

static const unsigned char server_cert[] =
{   "-----BEGIN CERTIFICATE-----\r\n"
    "MIIBGDCBvwIUXrph2YqyvLCnjevFIJlpYQ9SSHMwCgYIKoZIzj0EAwIwDTELMAkG\r\n"
    "A1UEAwwCQ0EwHhcNMjAwNTA4MTE0NzI3WhcNMzAwNTA2MTE0NzI3WjARMQ8wDQYD\r\n"
    "VQQDDAZzZXJ2ZXIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ1n415J3v5xyFj\r\n"
    "MhXBusaZm1y08vLnq8me8YIsd/pRiXrRaJ5+jq6K0tu4Jxdl3KnogExr1gyzVZqF\r\n"
    "lka6T0xWMAoGCCqGSM49BAMCA0gAMEUCIFfAXmfbPWFKuJM4uMYJShAShLfy/NmN\r\n"
    "rR99+Z8mK7c3AiEArlE5FAQmmyK0y3iiUGb6xcrj2o2zga3wbzWAeTNTCXM=\r\n"
    "-----END CERTIFICATE-----\r\n"
};
static const int server_cert_len = sizeof(server_cert);

static const unsigned char server_key[] =
{   "-----BEGIN EC PARAMETERS-----\r\n"
    "BggqhkjOPQMBBw==\r\n"
    "-----END EC PARAMETERS-----\r\n"
    "-----BEGIN EC PRIVATE KEY-----\r\n"
    "MHcCAQEEIOQ1fi6sT7QYV1kw0QmbLbF5frv0KLij1TIVak6tWPGMoAoGCCqGSM49\r\n"
    "AwEHoUQDQgAENZ+NeSd7+cchYzIVwbrGmZtctPLy56vJnvGCLHf6UYl60Wiefo6u\r\n"
    "itLbuCcXZdyp6IBMa9YMs1WahZZGuk9MVg==\r\n"
    "-----END EC PRIVATE KEY-----\r\n"
};
static const int server_key_len = sizeof(server_key);

static const unsigned char client_cert[] =
{   "-----BEGIN CERTIFICATE-----\r\n"
    "MIIBFzCBvwIUXrph2YqyvLCnjevFIJlpYQ9SSHQwCgYIKoZIzj0EAwIwDTELMAkG\r\n"
    "A1UEAwwCQ0EwHhcNMjAwNTA4MTE0ODA2WhcNMzAwNTA2MTE0ODA2WjARMQ8wDQYD\r\n"
    "VQQDDAZjbGllbnQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATYlGxUYxSQgapR\r\n"
    "Tzny8JfL5RSC5wYFjh8IbyJeEtCS2oI1a5V08qR2Bh74hXHHBbg7nyJHONoP0iTD\r\n"
    "eI9SvapWMAoGCCqGSM49BAMCA0cAMEQCIAuL8B9tG6XqX281RtumI4nZZUNhD854\r\n"
    "ab4dvQhxDNNYAiAzkENmSzdihnryI2WbyCnTat+nPIBmO+7SYCDsUVN8Mw==\r\n"
    "-----END CERTIFICATE-----\r\n"
};
static const int client_cert_len = sizeof(client_cert);

static const unsigned char client_key[] =
{   "-----BEGIN EC PARAMETERS-----\r\n"
    "BggqhkjOPQMBBw==\r\n"
    "-----END EC PARAMETERS-----\r\n"
    "-----BEGIN EC PRIVATE KEY-----\r\n"
    "MHcCAQEEILig1gurFAy2qoQHYSXorw1K36Qbzjj6KakstHcEn3OloAoGCCqGSM49\r\n"
    "AwEHoUQDQgAE2JRsVGMUkIGqUU858vCXy+UUgucGBY4fCG8iXhLQktqCNWuVdPKk\r\n"
    "dgYe+IVxxwW4O58iRzjaD9Ikw3iPUr2qVg==\r\n"
    "-----END EC PRIVATE KEY-----\r\n"
};
static const int client_key_len = sizeof(client_key);

static const unsigned char ca_cert[] =
{   "-----BEGIN CERTIFICATE-----\r\n"
    "MIIBcDCCARWgAwIBAgIUN3bvT1cqWsJGyTybgT0Ac5ACLxgwCgYIKoZIzj0EAwIw\r\n"
    "DTELMAkGA1UEAwwCQ0EwHhcNMjAwNTA4MTEzMjI2WhcNMzAwNTA2MTEzMjI2WjAN\r\n"
    "MQswCQYDVQQDDAJDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDPOzRHPoaOX\r\n"
    "W4HFkX0hvPZwrk/5LfoCMcJ5hHwnz1i+B9V/o285YNZ4+C2tPNXqOEZxv+Ii3o7u\r\n"
    "Lv9ZX0jLj4WjUzBRMB0GA1UdDgQWBBTW0s8WFzYmjIOEUlK+NZJ/y9ezSDAfBgNV\r\n"
    "HSMEGDAWgBTW0s8WFzYmjIOEUlK+NZJ/y9ezSDAPBgNVHRMBAf8EBTADAQH/MAoG\r\n"
    "CCqGSM49BAMCA0kAMEYCIQD1S30UpIK9dQU0g3YNwoB2YbgHLxzyNnXeKxcDmkg1\r\n"
    "nwIhAJVK9pxda/UInDak3WydBK+lvCXiVhW998l+mS05trUy\r\n"
    "-----END CERTIFICATE-----\r\n"
};
static const int ca_cert_len = sizeof(ca_cert);

#endif