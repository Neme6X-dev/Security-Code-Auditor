/**
 * vulnerable_sample.c
 *
 * Exemple de code C volontairement vulnérable pour les tests.
 * Contient trois types de vulnérabilités classiques :
 *   1. Buffer overflow via strcpy
 *   2. Memory leak (malloc sans free)
 *   3. Injection de commande via system()
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 1. Buffer overflow : strcpy sans contrôle de taille */
void copy_user_input(const char *user_input) {
    char buffer[64];
    strcpy(buffer, user_input); /* DANGEREUX : pas de vérification de la longueur */
    printf("Copié : %s\n", buffer);
}

/* 2. Memory leak : malloc sans free */
void allocate_and_leak(size_t size) {
    char *data = (char *)malloc(size);
    if (data == NULL) {
        return;
    }
    memset(data, 0, size);
    printf("Données allouées à l'adresse %p\n", (void *)data);
    /* data n'est jamais libéré → fuite mémoire */
}

/* 3. Injection de commande : system() avec variable utilisateur */
void run_command(const char *user_cmd) {
    char command[256];
    snprintf(command, sizeof(command), "echo %s", user_cmd);
    system(command); /* DANGEREUX : injection de commande possible */
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <input_string> <command>\n", argv[0]);
        return 1;
    }

    copy_user_input(argv[1]);
    allocate_and_leak(128);
    run_command(argv[2]);

    return 0;
}
