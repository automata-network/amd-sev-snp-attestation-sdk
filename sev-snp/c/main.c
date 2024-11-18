#include "sev_snp.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

void print_report(uint8_t *report, int length) {
    for(int i = 0; i < length; i++) {
        printf("%d ", report[i]);
    }
    printf("\n\n");
}

void print_report_data(uint8_t *report) {
    for(int i = 0x50; i < 0x90; i++) {
        printf("%d ", report[i]);
    }
    printf("\n\n");
}

int main(void)
{
    uint8_t *report, *vek_cert;

    uint8_t report_data[64] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        10, 149, 159, 135, 234, 252, 82, 188, 247, 89, 192, 87, 74, 51, 116, 21,
        66, 75, 226, 217, 200, 252, 163, 105, 40, 244, 55, 191, 8, 21, 211, 138
    };
    uintptr_t length = generate_attestation_report_with_options(report_data, 1);
    report = malloc(length);
    get_attestation_report_raw(report);

    // Double check that the report_data bytes are fine
    print_report_data(report);

    uintptr_t length2 = generate_vek_cert(report);

    // Double check that the report_data bytes are fine
    print_report_data(report);

    vek_cert = malloc(length2);
    get_vek_cert(vek_cert);

    print_report(report, length);

    free(report);
    free(vek_cert);
    return 0;
}