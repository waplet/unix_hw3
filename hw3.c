#include <stdio.h>
#include <math.h>
#include <mpi.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/md5.h>

// static const char attack[33] = "ac627ab1ccbdb62ec96e702f07f6425b"; // 99
static const char attack[33] = "b706835de79a2b4e80506f582af3676a"; // 999
// static const char attack[33] = "fa246d0262c3925617b0c72bb20eeb1d"; // 9999
// static const char attack[33] = "66d9978935150b34b9dc0741bc642be2"; // Dunte
static char found = 0;

/** http://codereview.stackexchange.com/questions/38474/brute-force-algorithm-in-c **/
static const char alphabet[] =
"abcdefghijklmnopqrstuvwxyz"
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"0123456789";

static const int alphabetSize = sizeof(alphabet) - 1;

void bForce(char * str, int index, int maxDepth);
void prepForce(int maxLen);

/**
http://stackoverflow.com/questions/7627723/how-to-create-a-md5-hash-of-a-string-in-c
**/
char *str2md5(const char *str);
int matches(const char *s1, const char *s2);

int main(int argc, char *argv[])
{
	int rank, size;
	MPI_Init(&argc, &argv);
	MPI_Comm_rank(MPI_COMM_WORLD, &rank);
	MPI_Comm_size(MPI_COMM_WORLD, &size);
	prepForce(4);
	MPI_Finalize();

	return 0;
}


int matches(const char *s1, const char *s2)
{
	if (strncmp(s1, s2, 32) == 0) {
		return 1;
	}

	return 0;
}

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


void bForce(char * str, int index, int maxDepth)
{
	for (int i = 0; i < alphabetSize; ++i) {
		str[index] = alphabet[i];

		if (index == maxDepth -1) {
			// This is a legit word, so there needs to be md5 checksum check.

			if (matches(str2md5(str), attack)) {
				printf("Match found for attack: %s (%s)\n", str, attack);
				found = 1;
				break;
			}
			// printf("%s\n", str);
		} else {
			bForce(str, index +1, maxDepth);
		}
	}
}

void prepForce(int maxLen)
{
	// Inits memory for string
	char * emptyString = malloc(maxLen + 1);

	for (int i = 1; i <= maxLen; ++i) {
		memset(emptyString, 0, maxLen + 1);
		if (found == 0) {
			bForce(emptyString, 0, i);
		}
	}

	free(emptyString);
}