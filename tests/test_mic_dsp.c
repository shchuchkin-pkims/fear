/**
 * @file test_mic_dsp.c
 * @brief Обработка микрофонного сигнала: чувствительность и ворота
 *
 * Проверяется не «функция отработала», а то, ради чего она написана: фон в
 * паузах глохнет, речь проходит целиком, и никакая настройка не превращает
 * звук в треск переполнения.
 */

#include "mic_dsp.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int checks = 0, failures = 0;

#define CHECK(cond) do {                                        \
    checks++;                                                   \
    if (!(cond)) {                                              \
        failures++;                                             \
        printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);  \
    }                                                           \
} while (0)

#define FRAME 480          /* 10 мс при 48 кГц */

/** Ровный шум заданной громкости, воспроизводимый от запуска к запуску. */
static void fill_noise(int16_t *buf, size_t n, float amp, unsigned *seed) {
    for (size_t i = 0; i < n; i++) {
        *seed = *seed * 1103515245u + 12345u;
        const float r = (float)((int)((*seed >> 16) & 0x7FFF) - 16384) / 16384.0f;
        buf[i] = (int16_t)(r * amp);
    }
}

/** Синус на 300 Гц - грубая замена голосу: он проходит фильтр верхних частот. */
static void fill_tone(int16_t *buf, size_t n, float amp, double *phase) {
    for (size_t i = 0; i < n; i++) {
        buf[i] = (int16_t)(sin(*phase) * amp);
        *phase += 2.0 * 3.14159265358979 * 300.0 / 48000.0;
    }
}

static float rms_of(const int16_t *buf, size_t n) {
    double s = 0;
    for (size_t i = 0; i < n; i++) s += (double)buf[i] * buf[i];
    return (float)sqrt(s / (double)n);
}

int main(void) {
    int16_t frame[FRAME];
    unsigned seed;
    double phase;

    /* --- выключенная обработка ничего не портит ------------------------- */
    {
        mic_dsp_t d;
        mic_dsp_init(&d, 0.0f, MIC_NS_OFF, 48000);
        seed = 1; phase = 0;
        fill_tone(frame, FRAME, 8000.0f, &phase);
        const float before = rms_of(frame, FRAME);
        mic_dsp_process(&d, frame, FRAME);
        const float after = rms_of(frame, FRAME);
        /* Фильтр верхних частот на 300 Гц почти не сказывается. */
        CHECK(after > before * 0.8f);
    }

    /* --- ворота глушат ровный фон --------------------------------------
     *
     * Это и есть то, ради чего всё написано: в паузах собеседник не должен
     * слышать чужой вентилятор.
     */
    {
        mic_dsp_t d;
        mic_dsp_init(&d, 0.0f, MIC_NS_MEDIUM, 48000);
        seed = 7;
        float first = 0.0f, last = 0.0f;
        for (int i = 0; i < 200; i++) {
            fill_noise(frame, FRAME, 300.0f, &seed);
            if (i == 0) first = rms_of(frame, FRAME);
            mic_dsp_process(&d, frame, FRAME);
            if (i == 199) last = rms_of(frame, FRAME);
        }
        CHECK(first > 0.0f);
        CHECK(last < first * 0.5f);
    }

    /* --- речь проходит, и проходит с самого начала ----------------------
     *
     * Срезанное начало слова - самый заметный на слух дефект ворот, поэтому
     * проверяется именно первый кадр речи после долгой тишины.
     */
    {
        mic_dsp_t d;
        mic_dsp_init(&d, 0.0f, MIC_NS_MEDIUM, 48000);
        seed = 11; phase = 0;
        for (int i = 0; i < 200; i++) {           /* тишина с фоном */
            fill_noise(frame, FRAME, 300.0f, &seed);
            mic_dsp_process(&d, frame, FRAME);
        }
        fill_tone(frame, FRAME, 8000.0f, &phase); /* первое слово */
        const float before = rms_of(frame, FRAME);
        mic_dsp_process(&d, frame, FRAME);
        const float after = rms_of(frame, FRAME);
        /* Ворота открываются не мгновенно, но первый же кадр должен быть
         * слышен, а не подавлен до уровня фона. */
        CHECK(after > before * 0.3f);

        /* А через несколько кадров - в полный голос. */
        for (int i = 0; i < 5; i++) {
            fill_tone(frame, FRAME, 8000.0f, &phase);
            mic_dsp_process(&d, frame, FRAME);
        }
        CHECK(rms_of(frame, FRAME) > before * 0.85f);
    }

    /* --- чувствительность --------------------------------------------- */
    {
        mic_dsp_t loud, quiet;
        mic_dsp_init(&loud,   6.0f, MIC_NS_OFF, 48000);
        mic_dsp_init(&quiet, -6.0f, MIC_NS_OFF, 48000);

        int16_t a[FRAME], b[FRAME];
        phase = 0; fill_tone(a, FRAME, 4000.0f, &phase);
        memcpy(b, a, sizeof a);
        mic_dsp_process(&loud,  a, FRAME);
        mic_dsp_process(&quiet, b, FRAME);
        /* +6 дБ - примерно вдвое, -6 дБ - примерно вполовину. */
        CHECK(rms_of(a, FRAME) > rms_of(b, FRAME) * 3.0f);
    }

    /* --- усиление насыщает, а не переполняет ----------------------------
     *
     * Переполнение int16 звучит как треск - громче любого шума, который мы
     * тут убираем. Проверяем, что громкий сигнал с большим усилением не
     * меняет знак.
     */
    {
        mic_dsp_t d;
        mic_dsp_init(&d, 24.0f, MIC_NS_OFF, 48000);
        for (size_t i = 0; i < FRAME; i++) frame[i] = 30000;
        mic_dsp_process(&d, frame, FRAME);
        int negatives = 0;
        for (size_t i = 0; i < FRAME; i++) if (frame[i] < 0) negatives++;
        /* Фильтр верхних частот убирает постоянную составляющую, поэтому
         * сигнал спадает к нулю - но через край уйти не должен нигде. */
        CHECK(negatives == 0);
    }

    /* --- предел усиления назван и соблюдается --------------------------- */
    {
        mic_dsp_t a, b;
        mic_dsp_init(&a, 100.0f, MIC_NS_OFF, 48000);
        mic_dsp_init(&b,  24.0f, MIC_NS_OFF, 48000);
        CHECK(fabsf(a.gain - b.gain) < 0.001f);

        mic_dsp_init(&a, -100.0f, MIC_NS_OFF, 48000);
        mic_dsp_init(&b,  -24.0f, MIC_NS_OFF, 48000);
        CHECK(fabsf(a.gain - b.gain) < 0.001f);
    }

    /* --- разбор имени уровня ------------------------------------------- */
    {
        mic_ns_level_t l;
        CHECK(mic_ns_from_string("off", &l) == 0 && l == MIC_NS_OFF);
        CHECK(mic_ns_from_string("low", &l) == 0 && l == MIC_NS_LOW);
        CHECK(mic_ns_from_string("medium", &l) == 0 && l == MIC_NS_MEDIUM);
        CHECK(mic_ns_from_string("high", &l) == 0 && l == MIC_NS_HIGH);
        CHECK(mic_ns_from_string("сильнее", &l) != 0);
        CHECK(mic_ns_from_string(NULL, &l) != 0);
    }

    /* --- пустой кадр не роняет ----------------------------------------- */
    {
        mic_dsp_t d;
        mic_dsp_init(&d, 0.0f, MIC_NS_MEDIUM, 48000);
        mic_dsp_process(&d, NULL, 10);
        mic_dsp_process(&d, frame, 0);
        mic_dsp_process(NULL, frame, FRAME);
        CHECK(1);
    }

    printf("test_mic_dsp: %d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
