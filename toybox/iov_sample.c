#include <stdio.h>
#include <sys/uio.h>
#include <stdbool.h>
#include <stdlib.h>
#include<fcntl.h>

struct sample_struct {
    size_t data_len;
    bool   is_ok;
    void *data;
};

int main()
{
    struct iovec iov[3];
    char content_data[200] = "AAAAAAAAAA";
    struct sample_struct sample;
    sample.is_ok = true;
    sample.data_len = 10;
    sample.data = content_data;

    iov[0].iov_base = &sample;
    iov[0].iov_len = sizeof(size_t) + sizeof(bool);
    iov[1].iov_base = sample.data;
    iov[1].iov_len = sample.data_len;

    FILE *fp;
    fp = fopen("iov_struct.bin", "wb");
    if (fp == NULL) {
        printf("Failed to open file\n");
        return 1;
    }
    ssize_t nwritten = writev(fileno(fp), iov, 2);
    printf("%zu bytes wiritten to file\n", nwritten);
    fclose(fp);

    fp = fopen("iov_struct.bin", "rb");
    struct sample_struct new_sample;
    fread(&new_sample, sizeof(size_t), 1, fp);
    fread(&new_sample+sizeof(size_t), sizeof(bool), 1, fp);
    char *data;
    data = (char *)malloc(sizeof(char) * new_sample.data_len);
    fread(data, sizeof(char), new_sample.data_len, fp);
    new_sample.data = data;

    printf("new_sample.data_len=%zu\n", new_sample.data_len);
    printf("new_sample.is_ok=%d\n", new_sample.is_ok);
    printf("new_sample.data=%.*s\n", (int)new_sample.data_len, (char *)new_sample.data);
    fclose(fp);
    free(data);

    return 0;
}