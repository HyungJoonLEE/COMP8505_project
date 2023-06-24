#ifndef COMP8505_PROJECT_LINKEDLIST_H
#define COMP8505_PROJECT_LINKEDLIST_H

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define FALSE 0
#define TRUE 1

typedef struct ListNodeType {
    char file_name[20];
    struct ListNodeType *pLink;
} ListNode;

typedef struct LinkedListType {
    int currentElementCount;
    ListNode headerNode;
} LinkedList;

LinkedList *createLinkedList(void);
int addLLElement(LinkedList *pList, int position, ListNode element);
int removeLLElement(LinkedList *pList, int position);
ListNode *getLLElement(LinkedList *pList, int position);

void clearLinkedList(LinkedList *pList);
int getLinkedListLength(LinkedList *pList);
void deleteLinkedList(LinkedList *pList);

#endif //COMP8505_PROJECT_LINKEDLIST_H
