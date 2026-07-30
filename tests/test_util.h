/**
 * @file test_util.h
 * @brief Minimal assertion harness for F.E.A.R. unit tests.
 *
 * No external framework: each test binary is a plain executable that
 * returns 0 on success and 1 if any CHECK failed, so it plugs straight
 * into CTest.
 */
#ifndef FEAR_TEST_UTIL_H
#define FEAR_TEST_UTIL_H

#include <stdio.h>
#include <string.h>

static int t_checks = 0;
static int t_failures = 0;

#define CHECK(cond) do {                                                  \
    t_checks++;                                                           \
    if (!(cond)) {                                                        \
        t_failures++;                                                     \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);   \
    }                                                                     \
} while (0)

/* Print a summary and return the process exit code. */
static int t_report(const char *suite) {
    if (t_failures) {
        fprintf(stderr, "%s: %d/%d checks FAILED\n", suite, t_failures, t_checks);
        return 1;
    }
    printf("%s: all %d checks passed\n", suite, t_checks);
    return 0;
}

#endif /* FEAR_TEST_UTIL_H */
