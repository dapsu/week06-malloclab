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

// Basic constants and macors
#define WSIZE       4           // Word and header/footer size(bytes)
#define DSIZE       8           // Double word size (btyes)
#define CHUNKSIZE   (1 << 12)   // Extend heap by this amount (bytes) : 초기 가용 블록과 힙 확장을 위한 기본 크기
#define MINIMUM     16          // header + pred + succ + footer = 16byte

#define MAX(x, y)   ((x) > (y) ? (x) : (y))    // x > y가 참이면 x, 거짓이면 y

// PACK매크로 : 크기와 할당 비트를 통합해서 header와 footer에 저장할 수 있는 값 리턴
#define PACK(size, alloc)   ((size) | (alloc))

// Read and wirte a word at address
#define GET(p)  (*(unsigned int *)(p))
#define PUT(p, val)  (*(unsigned int *)(p) = (val))

// Read the size and allocated field from address p
#define GET_SIZE(p)    (GET(p) & ~0x7)  // header or footer의 사이즈 반환(8의 배수)
#define GET_ALLOC(p)   (GET(p) & 0x1)   // 현재 블록 가용 여부 판단(0이면 alloc, 1이면 free)

// bp(현재 블록의 포인터)로 현재 블록의 header 위치와 footer 위치 반환
#define HDRP(bp)    ((char *)(bp) - WSIZE)
#define FTRP(bp)    ((char *)(bp) + GET_SIZE(HDRP(bp))-DSIZE)

// 다음과 이전 블록의 포인터 반환
#define NEXT_BLKP(bp)   (((char *)(bp) + GET_SIZE((char *)(bp) - WSIZE)))    // 다음 블록 bp 위치 반환(bp + 현재 블록의 크기)
#define PREV_BLKP(bp)   (((char *)(bp) - GET_SIZE((char *)(bp) - DSIZE)))    // 이전 블록 bp 위치 반환(bp - 이전 블록의 크기)

// free block의 bp 반환
#define SUCC_P(bp)  (*(char **)(bp + WSIZE))      //
#define PRED_P(bp)  (*(char **)(bp))              // free list에서 이전 프리 블럭을 가리킴

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
    PUT(heap_listp + (2*WSIZE), 0);                     // pred
    PUT(heap_listp + (3*WSIZE), 0);                     // succ
    PUT(heap_listp + MINIMUM, PACK(MINIMUM, 1));        // 블록의 footer
    PUT(heap_listp + WSIZE + MINIMUM, PACK(0, 1));      // Epilogue header

    free_listp = heap_listp + DSIZE;                    // header 뒤에 위치

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
    if (size == 0) {
        return NULL;
    }

    // Adjust block size to include overhead and alignment reqs
    if (size <= DSIZE) {    // 2words 이하의 사이즈는 4워드로 할당 요청 (header 1word, footer 1word)
        a_size = 2*DSIZE;
    }
    else {                  // 할당 요청의 용량이 2words 초과 시, 충분한 8byte의 배수의 용량 할당
        a_size = DSIZE * ((size + (DSIZE) + (DSIZE-1)) / DSIZE);
    }

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
    char *old_bp = bp;
    char *new_bp;
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

// void *mm_realloc(void *bp, size_t size) {
// 	if ((int)size < 0)
// 		return NULL;
// 	else if ((int)size == 0) {
// 		mm_free(bp);
// 		return NULL;
// 	}
// 	else if (size > 0) {
// 		size_t oldsize = GET_SIZE(HDRP(bp));
// 		size_t newsize = size + (2 * WSIZE); // 2 words for header and footer
// 		/*if newsize가 oldsize보다 작거나 같으면 그냥 그대로 써도 됨. just return bp */
// 		if (newsize <= oldsize) {
// 			return bp;
// 		}
// 		//oldsize 보다 new size가 크면 바꿔야 함.*/
// 		else {
// 			size_t next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(bp)));
// 			size_t csize;
// 			/* next block is free and the size of the two blocks is greater than or equal the new size  */
// 			/* next block이 가용상태이고 old, next block의 사이즈 합이 new size보다 크면 그냥 그거 바로 합쳐서 쓰기  */
// 			if (!next_alloc && ((csize = oldsize + GET_SIZE(HDRP(NEXT_BLKP(bp))))) >= newsize) {
// 				remove_block(NEXT_BLKP(bp));
// 				PUT(HDRP(bp), PACK(csize, 1));
// 				PUT(FTRP(bp), PACK(csize, 1));
// 				return bp;
// 			}
// 			// 아니면 새로 block 만들어서 거기로 옮기기
// 			else {
// 				void *new_ptr = mm_malloc(newsize);
// 				place(new_ptr, newsize);
// 				memcpy(new_ptr, bp, newsize);
// 				mm_free(bp);
// 				return new_ptr;
// 			}
// 		}
// 	}
// 	else
// 		return NULL;
// }

static void *extend_heap(size_t words) {
    char *bp;
    size_t size;

    // Allocate an even number of words  to maintain alignment
    size = (words % 2) ? (words+1) * WSIZE : words * WSIZE; // words가 홀수면 +1을 해서 공간 할당

    if (size < MINIMUM) {
        size = MINIMUM;
    }

    if ((int)(bp = mem_sbrk(size)) == -1) {
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
    char *bp;

    for (bp = free_listp; !GET_ALLOC(HDRP(bp)); bp = SUCC_P(bp)) {
        if (a_size <= GET_SIZE(HDRP(bp))) {
            return bp;
        }
    }
    return NULL;
}

static void *coalesce(void *bp) {
    size_t prev_alloc = GET_ALLOC(FTRP(PREV_BLKP(bp))) || PREV_BLKP(bp) == bp;  // PREV_BLKP(bp) == bp <-- epilogue block 만났을 경우
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

    // inserts tje free block pointer in the free_list
    SUCC_P(bp) = free_listp;
    PRED_P(free_listp) = bp;
    PRED_P(bp) = NULL;
    free_listp = bp;

    return bp;
}

// 할당 블록 연결 끊기
static void remove_block(void *bp) {
    if (PRED_P(bp)) {                       // 이전 블록이 할당 되어 있을 때
        SUCC_P(PRED_P(bp)) = SUCC_P(bp);    // 이전 블록에 뒤의 블록 주소 넣기
    }
    else {                                  // 이전 블록이 없을 때
        free_listp = SUCC_P(bp);            // 현 블록 없애고 뒷 블록에 가장 앞의 주소 넣기
    }
    PRED_P(SUCC_P(bp)) = PRED_P(bp);
}