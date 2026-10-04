/**
 * @file mic_dsp.c
 * @brief Реализация обработки микрофонного сигнала
 */

#include "mic_dsp.h"

#include <math.h>
#include <string.h>

/* Срез фильтра верхних частот. Ниже этого в человеческом голосе нет ничего:
 * там живут гул сети, шаги по полу, стук по столу и ветер в микрофон. */
#define MIC_HP_HZ 80.0f

/* Оценка фона движется вниз быстро, вверх медленно.
 *
 * Наоборот было бы хуже всего: заговорил человек - оценка фона поползла бы
 * к уровню его голоса, ворота захлопнулись бы прямо посреди фразы. Вверх
 * она идёт медленно, чтобы к постепенно нарастающему шуму привыкать, а не
 * принимать каждый чужой чих за новый фон. */
#define MIC_FLOOR_DOWN 0.15f
#define MIC_FLOOR_UP   0.0015f

/* Ворота открываются быстро, закрываются медленно.
 *
 * Быстро открываются, потому что иначе срезалось бы начало слова - самый
 * заметный на слух дефект. Медленно закрываются, чтобы не резать хвост
 * фразы и не «дышать» на каждой паузе между словами. */
#define MIC_GATE_OPEN  0.5f
#define MIC_GATE_CLOSE 0.02f

/* Сколько кадров набирается оценка фона, прежде чем воротам верить.
 * До этого ворота открыты: лучше пропустить секунду шума, чем срезать
 * первое слово разговора. */
#define MIC_PRIME_FRAMES 25

static void ns_params(mic_ns_level_t ns, float *thresh_k, float *floor_gain) {
    switch (ns) {
        case MIC_NS_LOW:    *thresh_k = 2.0f; *floor_gain = 0.50f; break;
        case MIC_NS_MEDIUM: *thresh_k = 3.0f; *floor_gain = 0.22f; break;
        case MIC_NS_HIGH:   *thresh_k = 4.5f; *floor_gain = 0.06f; break;
        default:            *thresh_k = 0.0f; *floor_gain = 1.00f; break;
    }
}

void mic_dsp_init(mic_dsp_t *d, float gain_db, mic_ns_level_t ns, int rate) {
    if (!d) return;
    memset(d, 0, sizeof *d);

    /* Предел не вкусовой: за +24 дБ микрофон превращается в источник
     * собственного шума, усиленного вместе с голосом. */
    if (gain_db >  24.0f) gain_db =  24.0f;
    if (gain_db < -24.0f) gain_db = -24.0f;
    d->gain = powf(10.0f, gain_db / 20.0f);

    d->ns = ns;
    if (rate <= 0) rate = 48000;
    const float rc = 1.0f / (2.0f * 3.14159265f * MIC_HP_HZ);
    const float dt = 1.0f / (float)rate;
    d->hp_a = rc / (rc + dt);

    d->gate = 1.0f;
    d->noise_floor = 0.0f;
    d->primed = 0;
}

void mic_dsp_process(mic_dsp_t *d, int16_t *pcm, size_t n) {
    if (!d || !pcm || n == 0) return;

    /* --- 1. Фильтр верхних частот -------------------------------------- */
    float sum_sq = 0.0f;
    for (size_t i = 0; i < n; i++) {
        const float x = (float)pcm[i];
        const float y = d->hp_a * (d->hp_y1 + x - d->hp_x1);
        d->hp_x1 = x;
        d->hp_y1 = y;
        pcm[i] = (int16_t)(y < -32768.0f ? -32768.0f : (y > 32767.0f ? 32767.0f : y));
        sum_sq += y * y;
    }
    const float rms = sqrtf(sum_sq / (float)n);

    /* --- 2. Оценка фона и ворота --------------------------------------- */
    float target = 1.0f;
    if (d->ns != MIC_NS_OFF) {
        if (d->primed < MIC_PRIME_FRAMES) {
            /* Первые кадры просто набираем среднее: считать их речью или
             * тишиной у нас пока нет оснований. */
            d->noise_floor = (d->primed == 0)
                ? rms
                : d->noise_floor * 0.8f + rms * 0.2f;
            d->primed++;
        } else {
            const float a = (rms < d->noise_floor) ? MIC_FLOOR_DOWN : MIC_FLOOR_UP;
            d->noise_floor += a * (rms - d->noise_floor);
        }

        float thresh_k, floor_gain;
        ns_params(d->ns, &thresh_k, &floor_gain);

        if (d->primed >= MIC_PRIME_FRAMES) {
            /* Нижняя граница порога нужна для тихой комнаты: там оценка фона
             * уходит почти в ноль, и без неё воротами открывался бы любой
             * шорох, помноженный на усиление. */
            const float thresh = fmaxf(d->noise_floor * thresh_k, 40.0f);
            target = (rms > thresh) ? 1.0f : floor_gain;
        }
    }

    const float a = (target > d->gate) ? MIC_GATE_OPEN : MIC_GATE_CLOSE;
    d->gate += a * (target - d->gate);

    /* --- 3. Ворота и чувствительность ---------------------------------- */
    const float k = d->gate * d->gain;
    if (k != 1.0f) {
        for (size_t i = 0; i < n; i++) {
            float v = (float)pcm[i] * k;
            /* Насыщение, а не перенос через край: переполнение int16 звучит
             * как треск, который громче любого исходного шума. */
            if (v >  32767.0f) v =  32767.0f;
            if (v < -32768.0f) v = -32768.0f;
            pcm[i] = (int16_t)v;
        }
    }
}

int mic_ns_from_string(const char *s, mic_ns_level_t *out) {
    if (!s || !out) return -1;
    if (strcmp(s, "off")    == 0) { *out = MIC_NS_OFF;    return 0; }
    if (strcmp(s, "low")    == 0) { *out = MIC_NS_LOW;    return 0; }
    if (strcmp(s, "medium") == 0) { *out = MIC_NS_MEDIUM; return 0; }
    if (strcmp(s, "high")   == 0) { *out = MIC_NS_HIGH;   return 0; }
    return -1;
}
