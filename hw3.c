#include <stdio.h>
#include <math.h>
#include <mpi.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/md5.h>

// static const char attack[33] = "ac627ab1ccbdb62ec96e702f07f6425b"; // 99
// static const char attack[33] = "b706835de79a2b4e80506f582af3676a"; // 999
// static const char attack[33] = "74b87337454200d4d33f80c4663dc5e5"; // aaaa
// static const char attack[33] = "fa246d0262c3925617b0c72bb20eeb1d"; // 9999
// static const char attack[33] = "cd64bab47ba44d4b4c2d63a45252a2eb"; // 9a9a
// static const char attack[33] = "594f803b380a41396ed63dca39503542"; // aaaaa
static const char attack[33] = "66d9978935150b34b9dc0741bc642be2"; // Dunte
static char found = 0;

/** http://codereview.stackexchange.com/questions/38474/brute-force-algorithm-in-c **/
static const char alphabet[] =
"abcdefghijklmnopqrstuvwxyz"
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"0123456789";

static const int alphabetSize = sizeof(alphabet) - 1;

/** headers for bruteforce function */
void bForce(char * str, int index, int maxDepth, int from, int to);
void prepForce(int maxLen, int from, int to);

/**
http://stackoverflow.com/questions/7627723/how-to-create-a-md5-hash-of-a-string-in-c
**/
char *str2md5(const char *str);
char matches(const char *s1, const char *s2);

/** Globalize rank and size */
int rank, size;

/** Send to root process that there was a match found of md5 hashes*/
void sendFound()
{
    char found = 1;
    MPI_Send(&found, 1, MPI_CHAR, 0, 0, MPI_COMM_WORLD);
}

int main(int argc, char *argv[])
{
    int from, to;
    MPI_Init(&argc, &argv);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);
    // base process
    if (rank != 0 || size == 1) {
        // Making correct calculations possible
        int fakeSize = size - 1;
        int calcRank = rank;
        if (size == 1) {
            fakeSize = 1;
            calcRank = 1;
        }

        from = (calcRank - 1) * alphabetSize / fakeSize;
        to = calcRank * alphabetSize / fakeSize;
        if (to > alphabetSize) {
            to = alphabetSize;
        }

        // printf("From: %d; to: %d\n", from, to);
        prepForce(5, from, to);
    } else {
        char fnd;
        for (int other_rank = 1; other_rank < size; other_rank++) {
            // printf("Waiting to receive...\n");
            MPI_Recv(&fnd, 1, MPI_CHAR, other_rank, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
            // printf("Process %d sent found: %d\n", other_rank, (int) fnd);
            // printf("%d\n", (int)fnd);

            if ((int) fnd == 1) {
                MPI_Finalize();
                break;
            }
        }
    }

    return 0;
}


/** Checks if two strings matches of hash strings */
char matches(const char *s1, const char *s2)
{
    if (strncmp(s1, s2, 32) == 0) {
        return 1;
    }

    return 0;
}

/** Converts from chars* to md5 hex */
char *str2md5(const char *str)
{
    int n;
    MD5_CTX c;
    unsigned char digest[16];
    char *out = (char *)malloc(33);
    MD5_Init(&c);
    MD5_Update(&c, str, strlen(str));
    MD5_Final(digest, &c);

    for (n = 0; n < 16; ++n) {
        snprintf(&(out[n*2]), 16*2, "%02x", (unsigned int)digest[n]);
    }

    return out;
}


void bForce(char * str, int index, int maxDepth, int from, int to)
{
    // No need to bruteforce more if the match was found
    if (found == 1) {
        return;
    }

    // Lets calculate from based on rank
    if (index != 0) {
        from = 0;
        to = alphabetSize;
    }

    for (int i = from; i < to; ++i) {
        str[index] = alphabet[i];

        if (index == maxDepth -1) {
            // This is a legit word, so there needs to be md5 checksum check.
            if (matches(str2md5(str), attack)) {
                printf("Match found for attack: %s (%s)\n", str, attack);
                found = 1;

                if (size != 1) {
                    sendFound();
                }
                break;
            }
        } else {
            bForce(str, index +1, maxDepth, from, to);
        }
    }
}

void prepForce(int maxLen, int from, int to)
{
    // Inits memory for string
    char * emptyString = malloc(maxLen + 1);

    for (int i = 1; i <= maxLen; ++i) {
        memset(emptyString, 0, maxLen + 1);
        bForce(emptyString, 0, i, from, to);
    }

    free(emptyString);
}