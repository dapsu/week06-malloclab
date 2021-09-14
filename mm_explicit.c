/*
 * mm-naive.c - The fastest, least memory-efficient malloc package.
 * 
 * In this naive approach, a block is allocated by simply incrementing
 * the brk pointer.  A block is pure payload. There are no headers or
 * footers.  Blocks are never coalesced or reused. Realloc is
 * implemented directly using mm_malloc and mm_free.
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "mm.h"
#include "memlib.h"

/*********************************************************
 * NOTE TO STUDENTS: Before you do anything else, please
 * provide your team information in the following struct.
 ********************************************************/
team_t team = {
    /* Team name */
    "week06 fifth team",
    /* First member's full name */
    "Dapsu",
    /* First member's email address */
    "greenrock4@skku.edu",
    /* Second member's full name (leave blank if none) */
    "",
    /* Second member's email address (leave blank if none) */
    ""
};

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(p) (((size_t)(p) + (ALIGNMENT-1)) & ~0x7)   // ALIGNMENT와 가장 근접한 8배수(ALLIGNMENT배수)로 올림 

// Basic constants and macors
#define WSIZE       4           // Word and header/footer size(bytes)
#define DSIZE       8           // Double word size (btyes)
#define CHUNKSIZE   (1 << 12)   // Extend heap by this amount (bytes) : 초기 가용 블록과 힙 확장을 위한 기본 크기
#define MINIMUM     24

#define MAX(x, y)   ((x) > (y) ? (x) : (y))    // x > y가 참이면 x, 거짓이면 y

// PACK매크로 : 크기와 할당 비트를 통합해서 header와 footer에 저장할 수 있는 값 리턴
#define PACK(size, alloc)   ((size) | (alloc))

// Read and wirte a word at address
#define GET(p)  (*(unsigned int *)(p))
#define PUT(p, val)  (*(unsigned int *)(p) = (val))

// Read the size and allocated field from address p
#define GET_SIZE(p)    (GET(p) & ~0x7)  // header or footer의 사이즈 반환(8의 배수)
#define GET_ALLOC(p)   (GET(p) & 0x1)   // 현재 블록 가용 여부 판단(0이면 alloc, 1이면 free)

/* 블록포인터(bp)로 헤더와 푸터의 주소를 계산 */
#define HDRP(bp)    ((char *)(bp) - WSIZE)
#define FTRP(bp)    ((char *)(bp) + GET_SIZE(HDRP(bp))-DSIZE)

/* 블록포인터(bp)로 이전 블록과 다음 블록의 주소를 계산 */
#define NEXT_BLKP(bp)   (((char *)(bp) + GET_SIZE((char *)(bp) - WSIZE)))    // 다음 블록 bp 위치 반환(bp + 현재 블록의 크기)
#define PREV_BLKP(bp)   (((char *)(bp) - GET_SIZE((char *)(bp) - DSIZE)))    // 이전 블록 bp 위치 반환(bp - 이전 블록의 크기)

/* freeList의 이전 포인터와 다음 포인터 계산 */
#define NEXT_FLP(bp)  (*(char **)(bp + WSIZE))      // WSIZE나 DSIZE나 상관없다......(12도 노상관..)
#define PREV_FLP(bp)  (*(char **)(bp))              // free list에서 이전 프리 블럭을 가리킴

// Declaration
static void *heap_listp;
static void *free_listp;
static void *extend_heap(size_t words);
static void *coalesce(void *bp);
static void remove_block(void *bp);
static void *find_fit(size_t a_size);
static void place(void *bp, size_t a_size);


int mm_init(void)
{
    if ((heap_listp = mem_sbrk(2*MINIMUM)) == (void *)-1) {
        return -1;
    }

    PUT(heap_listp, 0);                                 // Alignment padding
    PUT(heap_listp + (1*WSIZE), PACK(MINIMUM, 1));      // Prologue header
    PUT(heap_listp + (2*WSIZE), 0);                     // 블록에서 p를 가리킬 위치
    PUT(heap_listp + (3*WSIZE), 0);                     // 블록에서 N을 가리킬 위치
    PUT(heap_listp + MINIMUM, PACK(MINIMUM, 1));        // 블록의 footer
    PUT(heap_listp + WSIZE + MINIMUM, PACK(0, 1));      // Epilogue header

    free_listp = heap_listp + DSIZE;                    // header 뒤로 free list 포인터 이동

    if (extend_heap(CHUNKSIZE/WSIZE) == NULL) {
        return -1;
    }

    return 0;
}

void *mm_malloc(size_t size) {
    size_t a_size;       // adjusted block szie
    size_t extend_size;  // Amount to extend heap if no fit
    char *bp;

    // Ignore spurious requests
    if (size <= 0) {
        return NULL;
    }

    a_size = MAX(MINIMUM, ALIGN(size) + DSIZE);

    if ((bp = find_fit(a_size))) {
        place(bp, a_size);
        return bp;
    }

    extend_size = MAX(a_size, CHUNKSIZE);

    if ((bp = extend_heap(extend_size/WSIZE)) == NULL) {
        return NULL;
    }
    place(bp, a_size);
    return bp;
}

void mm_free(void *bp) {
    size_t size = GET_SIZE(HDRP(bp));

    PUT(HDRP(bp), PACK(size, 0));
    PUT(FTRP(bp), PACK(size, 0));
    coalesce(bp);
}

void *mm_realloc(void *bp, size_t size) {
    void *old_bp = bp;
    void *new_bp;
    size_t copySize;
    
    new_bp = mm_malloc(size);
    if (new_bp == NULL)
      return NULL;
    copySize = GET_SIZE(HDRP(old_bp));
    if (size < copySize)
      copySize = size;
    memcpy(new_bp, old_bp, copySize);  // 메모리의 특정한 부분으로부터 얼마까지의 부분을 다른 메모리 영역으로 복사해주는 함수(old_bp로부터 copySize만큼의 문자를 new_bp로 복사해라)
    mm_free(old_bp);
    return new_bp;
}

static void *extend_heap(size_t words) {
    char *bp;
    size_t size;

    // Allocate an even number of words  to maintain alignment
    size = (words % 2) ? (words+1) * WSIZE : words * WSIZE; // words가 홀수면 +1을 해서 공간 할당

    if (size < MINIMUM) {
        size = MINIMUM;
    }

    if ((long)(bp = mem_sbrk(size)) == -1) {
        return NULL;
    }

    // initialize free block header/footer and the epilogue header
    PUT(HDRP(bp), PACK(size, 0));
    PUT(FTRP(bp), PACK(size, 0));
    PUT(HDRP(NEXT_BLKP(bp)), PACK(0, 1));
    /*
    extend_heap 블록 너머에 오지 않도록 배치한 블록 다음 공간을 블록이라 가정하고 epilogue header 배치
    (실제로는 존재하지 않는 블록)
    */

    // coalesce if the previous block was free
    return coalesce(bp);   
}

static void place(void *bp, size_t a_size) {
    size_t c_size = GET_SIZE(HDRP(bp));

    if ((c_size-a_size) >= MINIMUM) {
        PUT(HDRP(bp), PACK(a_size, 1));
        PUT(FTRP(bp), PACK(a_size, 1));
        remove_block(bp);

        bp = NEXT_BLKP(bp);

        PUT(HDRP(bp), PACK(c_size - a_size, 0));
        PUT(FTRP(bp), PACK(c_size - a_size, 0));
        coalesce(bp);
    }
    else {
        PUT(HDRP(bp), PACK(c_size, 1));
        PUT(FTRP(bp), PACK(c_size, 1));
        remove_block(bp);
    }
}

static void *find_fit(size_t a_size) {
    void *bp;

    for (bp = free_listp; GET_ALLOC(HDRP(bp)) == 0; bp = NEXT_FLP(bp)) {
        if (a_size <= (size_t)GET_SIZE(HDRP(bp))) {
            return bp;
        }
    }
    return NULL;
}

static void *coalesce(void *bp) {
    size_t prev_alloc = GET_ALLOC(FTRP(PREV_BLKP(bp))) || PREV_BLKP(bp) == bp;
    size_t next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(bp)));
    size_t size = GET_SIZE(HDRP(bp));

    // case1: 앞 블록 할당, 뒷 블록 가용
    if (prev_alloc && !next_alloc) {
        size += GET_SIZE(HDRP(NEXT_BLKP(bp)));
        remove_block(NEXT_BLKP(bp));
        PUT(HDRP(bp), PACK(size, 0));
        PUT(FTRP(bp), PACK(size, 0));
    }

    // case2: 앞 블록 가용, 뒷 블록 할당
    else if (!prev_alloc && next_alloc) {
        size += GET_SIZE(HDRP(PREV_BLKP(bp)));
        bp = PREV_BLKP(bp);
        remove_block(bp);
        PUT(HDRP(bp), PACK(size, 0));
        PUT(FTRP(bp), PACK(size, 0));
    }

    // case3: 앞, 뒤 블록 모두 가용
    else if (!prev_alloc && !next_alloc) {
        size += (GET_SIZE(HDRP(PREV_BLKP(bp))) + GET_SIZE(HDRP(NEXT_BLKP(bp))));
        remove_block(PREV_BLKP(bp));
        remove_block(NEXT_BLKP(bp));
        bp = PREV_BLKP(bp);
        PUT(HDRP(bp), PACK(size, 0));
        PUT(FTRP(bp), PACK(size, 0));
    }

    NEXT_FLP(bp) = free_listp;
    PREV_FLP(free_listp) = bp;
    PREV_FLP(bp) = NULL;
    free_listp = bp;

    return bp;
}

static void remove_block(void *bp) {
    if (PREV_FLP(bp)) {
        NEXT_FLP(PREV_FLP(bp)) = NEXT_FLP(bp);
    }
    else {
        free_listp = NEXT_FLP(bp);
    }
    PREV_FLP(NEXT_FLP(bp)) = PREV_FLP(bp);
}