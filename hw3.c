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
static unsigned char attackDigest[16];
static unsigned char testDigest[16];

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
void str2md5(const char *str, unsigned char *digest);
void hex2dig(const char *str, unsigned char *digest);
char matches(const unsigned char *s1, const unsigned char *s2);
void sendFound();

/** Globalize rank and size */
int rank, size;

int main(int argc, char *argv[])
{
    int from, to;
    // size = 1;
    // rank = 0;
    MPI_Init(&argc, &argv);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    // printf("Size: %d\n", size);
    // printf("Rank: %d\n", rank);
    // base process

    // Calculate attack md5 to 16byte digest
    hex2dig(attack, attackDigest);

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
            printf("Waiting to receive...\n");
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

/** Send to root process that there was a match found of md5 hashes*/
void sendFound()
{
    char found = 1;
    MPI_Send(&found, 1, MPI_CHAR, 0, 0, MPI_COMM_WORLD);
}

/** Checks if two strings matches of hash strings */
char matches(const unsigned char *s1, const unsigned char *s2)
{
    if (strncmp((char *)s1, (char *)s2, 16) == 0) {
        return 1;
    }

    return 0;
}

/** Converts from chars* to md5 hex */
void str2md5(const char *str, unsigned char *digest)
{
    MD5_CTX c;
    MD5_Init(&c);
    MD5_Update(&c, str, strlen(str));
    MD5_Final(digest, &c);
}

void hex2dig(const char *str, unsigned char * digest)
{
    unsigned char t = 0;
    char C[2];

    for (int i = 0; i < 32; ++i) {
        C[0] = str[i];
        C[1] = '\0';
        int num = strtol(C, NULL, 16);
        if (i % 2 == 1) {
            t += num;
            digest[(i-1) / 2] = t;
            t = 0;
        } else {
            t+= num * 16;
        }
    }
}

void bForce(char * str, int index, int maxDepth, int from, int to)
{
    // No need to bruteforce more if the match was found
    if (found == 1) {
        return;
    }

    // Lets reassigns default foreach positions if not first level
    if (index != 0) {
        from = 0;
        to = alphabetSize;
    }

    for (int i = from; i < to; ++i) {
        str[index] = alphabet[i];

        if (index == maxDepth -1) {
            // This is a legit word, so there needs to be md5 checksum check.
            str2md5(str, testDigest);
            if (matches(testDigest, attackDigest) == 1) {
                printf("Match found for attack: %s (%s)\n", str, attack);
                found = 1;
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
    char emptyString[maxLen];

    for (int i = 1; i <= maxLen; ++i) {
        memset(emptyString, 0, i + 1);
        bForce(emptyString, 0, i, from, to);
    }

    if (found == 1 && size != 1) {
        sendFound();
    }
}