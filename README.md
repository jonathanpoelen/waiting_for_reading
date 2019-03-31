```
waiting_for_reading filename command args...
```

When the `filename` file is fully read, a delay of 10 seconds during the reading is performed while waiting for additional data. This allows one program to read one file while another writes it.

```bash
wget ....../file.rar &
waiting_for_reading file.rar unrar x file.rar
```

Uses `ptrace.h`, only works on Linux.
