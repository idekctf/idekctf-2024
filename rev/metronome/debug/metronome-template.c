#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/shm.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>

#define n {n}
#define nbit (8 * n)
#define MAXPIDS (4 * n)
#define sq(x) ((x) * (x))

struct edge{
  int x, y;
};

struct bound{
  double min, max;
};

struct globstate{
  int num;
  int pids[MAXPIDS];
  double res[nbit];
};

char flag[n + 1];
struct edge edg[nbit] = {edg};
struct bound bnd[sq(nbit)] = {bnd};

void matmult(double x[2][2], double y[2][2]){
  double z[2][2] = {{0, 0}, {0, 0}};
  for(int i = 0; i < 2; i++)
  for(int j = 0; j < 2; j++)
  for(int l = 0; l < 2; l++){
    z[i][j] += x[i][l] * y[l][j];
  }
  memcpy(x, z, sizeof(z));
}

double mattest(int x, int y){
  double z = ((double)rand() / RAND_MAX) * 0.9 + 0.05;
  double a[2][2] = {{x, y}, {z, 1 - z}};

  for(int i = 0; i < 5; i++){
    matmult(a, a);
  }

  double ret = 0;
  for(int i = 0; i < 2; i++)
  for(int j = 0; j < 2; j++){
    ret += a[i][j];
  }

  return ret;
}

int getbit(int x){
  return (flag[x / 8] >> (x % 8)) & 1;
}

void flagtest(int cid, int idx){ 
  struct globstate *gs;
  int base_pid = getpid();
  for(int i = 0; i < 2; i++){
    int pid = fork();
    if(pid){
      gs = shmat(cid, NULL, 0);
      while(1){
	int x = rand() % MAXPIDS;
	if(!gs->pids[x]){
	  gs->num++;
	  gs->pids[x] = pid;
	  break;
	}
      }
    }
  }

  int pid = getpid(); 
  if(pid == base_pid) return;

  int ex = getbit(edg[idx].x), ey = getbit(edg[idx].y);
  gs->res[idx] = mattest(ex, ey);

  for(int i = 0; i < MAXPIDS; i++){
    if(gs->pids[i] == pid){
      gs->num--;
      gs->pids[i] = 0;
    }
  }

  exit(0);
}

int main(){
  srand(time(NULL));
   
  puts("Utaha will check your flag more or less: ");

  fgets(flag, n + 1, stdin);

  int cid = shmget(IPC_PRIVATE, sizeof(struct globstate), IPC_CREAT | 0666);

  for(int i = 0; i < nbit; i++) flagtest(cid, i);

  struct globstate *gs = shmat(cid, NULL, 0);

  usleep(10000);

  while(1){
    if(gs->num <= 5) break;

    int x = rand() % MAXPIDS;
    if(gs->pids[x] != 0){
      kill(gs->pids[x], SIGTERM);
      gs->num--;
      gs->pids[x] = 0;
    }    

    usleep(5000);
  }

  bool t = true;
  for(int i = 0; i < nbit; i++)
  for(int j = 0; j < nbit; j++){
    double x = gs->res[i] * gs->res[j];
    int idx = i * nbit + j;
    if(x < bnd[idx].min || x > bnd[idx].max){
      t = false;
      //printf("%d: %f * %f -> %f %f %f\n", idx, gs->res[i], gs->res[j], bnd[idx].min, x, bnd[idx].max);
      //puts("rip");
    }
  }

  if(t){
    puts("Utaha approves.");
  }else{
    puts("Utaha rejects.");
  }

  return 0;
}
