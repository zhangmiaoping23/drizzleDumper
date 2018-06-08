/*
 * drizzleDumper Code By Drizzle.Risk
 * file: drizzleDumper.c
 */

#include "drizzleDumper.h"

// 只支持dalvik虚拟机
// proc/pid/cmdline 启动时相关
// /proc/pid/task 子线程 
// /proc/pid/mem 进程持有的内存，不可读 
// /proc/pid/maps 内存映射 
// 未加壳的APP是找不到.dex的
int main(int argc, char *argv[]) {

  printf("[>>>]  This is drizzleDumper [<<<]\n");
  printf("[>>>]    code by Drizzle     [<<<]\n");
  printf("[>>>]        2016.05         [<<<]\n");
  if(argc <= 1) 
  {
    printf("[*]  Useage : ./drizzleDumper package_name wait_times(s)\n[*]  The wait_times(s) means how long between the two Scans, default 0s  \n[*]  if successed, you can find the dex file in /data/local/tmp\n[*]  Good Luck!\n");
    return 0;
  }

  //Check root
  if(getuid() != 0) 
  {
    printf("[*]  Device Not root!\n");
    return -1;
  }

  double wait_times = 0.01;
  if(argc >= 3)
  {
  	wait_times = strtod(argv[2], NULL);
	printf("[*]  The wait_times is %ss\n", argv[2]);
  }
  char *package_name = argv[1];

  printf("[*]  Try to Find %s\n", package_name);

  uint32_t pid = -1;

  int i = 0;
  int mem_file;
  uint32_t clone_pid;
  char *extra_filter;
  char *dumped_file_name;

  /*
   * Into the loop
   */
  while(1)
  {
    //wait some time
	  sleep(wait_times);
	  pid = -1;
	  pid = get_process_pid(package_name);

    //find process
	  if(pid < 1 || pid == -1)
	  {
		  continue;
	  }
	  printf("[*]  pid is %d\n", pid);

    //find cloned process(the last dir of /proc/pid/task) 
	  clone_pid = get_clone_pid(pid);
	  if(clone_pid <= 0) 
	  {
	    continue;
	  }
	  printf("[*]  clone pid is %d\n", clone_pid);

          memory_region memory;
          //ptrace cloned process
          printf("[*]  ptrace [clone_pid] %d\n", clone_pid);
       	  mem_file = attach_get_memory(clone_pid);
	  if(mem_file == -10201) 
	  {
	    //ptrace failed,other errors
	    continue;
	  }
	  else if(mem_file == -20402)
	  {
	     //proc/pid/mem open error
	     //continue;
	  }
	  else if(mem_file == -30903)
	  {
	     //ptrace failed,can't ptrace
	     //continue
	  }
	
	    /*
	     * Begin Scanning
	     */
	  dumped_file_name = malloc(strlen(static_safe_location) + strlen(package_name) + strlen(suffix));
	  sprintf(dumped_file_name, "%s%s%s", static_safe_location, package_name, suffix);
	  printf("[*]  Scanning dex ...\n");
	  if(find_magic_memory(clone_pid, mem_file, &memory, dumped_file_name) <= 0)
	  {
	    printf("[*]  The magic was Not Found!\n");
            ptrace(PTRACE_DETACH, clone_pid, NULL, 0);
            close(mem_file);
            continue;
	  }
	  else
	  {
        /*
         * Successed & exit
         */
         close(mem_file);
         ptrace(PTRACE_DETACH, clone_pid, NULL, 0);
         break;
	  }
   }

  printf("[*]  Done.\n\n");
  return 1;
}

uint32_t get_clone_pid(uint32_t service_pid)
{
  DIR *service_pid_dir;
  char service_pid_directory[1024];
  sprintf(service_pid_directory, "/proc/%d/task/", service_pid);

  if((service_pid_dir = opendir(service_pid_directory)) == NULL)
  {
    return -1;
  }

  struct dirent* directory_entry = NULL;
  struct dirent* last_entry = NULL;

  while((directory_entry = readdir(service_pid_dir)) != NULL)
  {
    last_entry = directory_entry;
  }

  if(last_entry == NULL)
    return -1;

  closedir(service_pid_dir);

  return atoi(last_entry->d_name);
}

uint32_t get_process_pid(const char *target_package_name)
{
  char self_pid[10];
  sprintf(self_pid, "%u", getpid());

  DIR *proc = NULL;

  if((proc = opendir("/proc")) == NULL)
    return -1;

  struct dirent *directory_entry = NULL;
  while((directory_entry = readdir(proc)) != NULL)
  {

    if (directory_entry == NULL)
      return -1;

    if ((strcmp(directory_entry->d_name, "self") == 0) || (strcmp(directory_entry->d_name, self_pid) == 0))
        continue;

      char cmdline[1024];
      snprintf(cmdline, sizeof(cmdline), "/proc/%s/cmdline", directory_entry->d_name);
      FILE *cmdline_file = NULL;
      if((cmdline_file = fopen(cmdline, "r")) == NULL)
		  continue;

      char process_name[1024];
      fscanf(cmdline_file, "%s", process_name);
      fclose(cmdline_file);

      if(strcmp(process_name, target_package_name) == 0)
      {
	       closedir(proc);
         return atoi(directory_entry->d_name);
      }
    }

    closedir(proc);
    return -1;
}

int find_magic_memory(uint32_t clone_pid, int memory_fd, memory_region *memory , const char *file_name) {
  int ret = 0;
  char maps[2048];
  snprintf(maps, sizeof(maps), "/proc/%d/maps", clone_pid);

  FILE *maps_file = NULL;
  if((maps_file = fopen(maps, "r")) == NULL)
  {
    printf(" [+] fopen %s Error  \n" , maps);
    return -1;
  }

   char mem_line[1024];
   //12c00000-12e01000 r--p 00000000 00:04 8555                               /dev/ashmem/dalvik-main space (deleted)
   while(fscanf(maps_file, "%[^\n]\n", mem_line) >= 0)
   {
    char mem_address_start[10]={0};
    char mem_address_end[10]={0};
    char mem_info[1024]={0};
    sscanf(mem_line, "%8[^-]-%8[^ ]%*s%*s%*s%*s%s", mem_address_start, mem_address_end,mem_info);
    memset(mem_line , 0 ,1024);
    uint32_t mem_start = strtoul(mem_address_start, NULL, 16);
    memory->start = mem_start;
    memory->end = strtoul(mem_address_end, NULL, 16);

	  int len =  memory->end - memory->start;

	  if(len <= 10000)
	  {//too small

		  continue;
	  }
	  else if(len >= 150000000)
	  {//too big
		  continue;
	  }

	  char each_filename[254] = {0};
	  char randstr[10] = {0};
	  sprintf(randstr ,"%d", rand()%9999 );

	  strncpy(each_filename , file_name , 200);
	  strncat(each_filename , randstr , 10);
	  strncat(each_filename , ".dex" , 4);
	  lseek64(memory_fd,0,SEEK_SET);
	  off_t r1 = lseek64(memory_fd , memory->start , SEEK_SET);
	  if(r1 == -1)
	  {
		 //do nothing
	  }
	  else
	  {
		char *buffer = malloc(len);
	 	ssize_t readlen = read(memory_fd, buffer, len);
		printf("meminfo: %s ,len: %d ,readlen: %d, start: 0x%x\n",mem_info, len, readlen, memory->start);
		
		//实际测试情况的内存情况
		// /system/framework/core.odex  
		// /data/dalvik-cache/data@data@de.robv.android.xposed.installer@bin@XposedBridge.jar@classes.dex
		// /data/dalvik-cache/data@app@com.appstore-1.apk@classes.dex
		// 均为 dey 036
		
		//00000000   7F 45 4C 46                                        .ELF
		if(buffer[1] == 'E' && buffer[2] == 'L' && buffer[3] == 'F')
		{
			free(buffer);

			continue;
		}
		
		//00000000   64 65 78 0A 30 33 35 00                            dex.035.
		if(buffer[0] == 'd' && buffer[1] == 'e' && buffer[2] == 'x' && buffer[3] == '\n'  && buffer[4] == '0' && buffer[5] == '3')
		{
			  printf(" [+] find dex, start : %d(0x%x), end %d(0x%x),memory len : %d , info : %s\n" , memory->start,memory->start,memory->end,memory->end,readlen , mem_info);
			  DexHeader header;
			  char real_lenstr[10]={0};
			  memcpy(&header , buffer ,sizeof(DexHeader));
			  sprintf(real_lenstr , "0x%x" , header.fileSize);		//注意观察文件大小是否超过内存块。这里可能需要根据实际文件大小，重新定位
			  long real_lennum = strtol(real_lenstr , NULL, 16);
			  printf(" [+] This dex's fileSize: %d\n", real_lennum);
			  printf(" [+] notice that this dex's fileSize(%d) is over than the memory size(%d)\n", real_lennum,readlen);	  

	  		if(dump_memory(buffer , len , each_filename)  == 1)
			  {
			          printf(" [+] dex dump into %s\n", each_filename);
			          free(buffer);
			          //continue; 找到不需要继续查找,猜测这里可能是为了multi-dex的支持，后期或许考虑用max_dex_count
			          ret = 1;
			          break;
			  }
			  else
			  {
			  	 printf(" [+] dex dump error \n");
			  }

	 	}
		free(buffer);
	   }


	   lseek64(memory_fd , 0 , SEEK_SET);	
	   r1 = lseek64(memory_fd , memory->start + 8 , SEEK_SET);
	   if(r1 == -1)
	   {
		   continue;
	   }
	   else
	   {
		  char *buffer = malloc(len);
	 	  ssize_t readlen = read(memory_fd, buffer, len);

		  if(buffer[0] == 'd' && buffer[1] == 'e' && buffer[2] == 'x' && buffer[3] == '\n'  && buffer[4] == '0' && buffer[5] == '3')
	 	  {
			  printf(" [+] find dex, start : %d(0x%x), end %d(0x%x),memory len : %d , info : %s\n" , memory->start,memory->start,memory->end,memory->end,readlen , mem_info);
			  DexHeader header;
			  char real_lenstr[10]={0};
			  memcpy(&header , buffer ,sizeof(DexHeader));
			  sprintf(real_lenstr , "0x%x" , header.fileSize);
			  long real_lennum = strtol(real_lenstr , NULL, 16);
			  printf(" [+] This dex's fileSize: %d\n", real_lennum);

	  		if(dump_memory(buffer , len , each_filename)  == 1)
			  {
                  printf(" [+] dex dump into %s\n", each_filename);
				  free(buffer);
				  //continue; 找到不需要继续查找，猜测这里可能是为了multi-dex的支持，后期或许考虑用max_dex_count
				  ret = 1;
				  break;
			  }
			  else
			  {
			  	 printf(" [+] dex dump error \n");
			  }
	 	  }
		  free(buffer);
	   }
  }
  fclose(maps_file);
  return ret;
}

/*
 * Dump buffer from Mem to file.
 */
int dump_memory(const char *buffer , int len , char each_filename[])
{
	int ret = -1;
	FILE *dump = fopen(each_filename, "wb");
	if(fwrite(buffer, len, 1, dump) != 1)
	{
  	    ret = -1;
	}
	else
	{
		ret = 1;
	}

	fclose(dump);
 	return ret;
}

// Perform all that ptrace magic,to get the mem of the pid
int attach_get_memory(uint32_t pid) {
  char mem[1024];
  bzero(mem,1024);
  snprintf(mem, sizeof(mem), "/proc/%d/mem", pid);

  // Attach to process so we can peek/dump
  int ret = -1;
  ret = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
  int mem_file;

  if (0 != ret)
  {	  //ptrace eeor 
	  int err = errno;	
	  if(err == 1) //EPERM
	  {
		  return -30903;	//have been ptraced or can't trace
	  }
	  else
	  {
		  return -10201;	//other errors(process can't be found or illegal operation)
	  }
  }
  else
  {	  
	  //ptrace success
	  if(!(mem_file = open(mem, O_RDONLY)))
	  {
	    return -20402;  	//open error
	  }
  }
  return mem_file;
}
