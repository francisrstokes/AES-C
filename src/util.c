#include "util.h"

size_t GetFileSize(FILE* fp) {
  fseek(fp, 0, SEEK_END);
  size_t fileSize = ftell(fp);
  rewind(fp);
  return fileSize;
}
