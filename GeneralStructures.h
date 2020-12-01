#pragma once
#ifndef BOTH_GeneralStructures_HEADER_INCLUDED
#define BOTH_GeneralStructures_HEADER_INCLUDED

#define MAX_PATH 260

typedef struct _AVL_TREE
{
	_AVL_TREE * LeftChild;
	_AVL_TREE * RightChild;
} AVL_TREE, *PAVL_TREE;

typedef struct _FunctionCallBack
{
	void * Function;
	void * Reserved;
} FunctionCallBack, *PFunctionCallBack;

typedef struct _SimpleLenghtQuery
{
	void* StartAddress;
	unsigned long long Size;
} SimpleLenghtQuery, * PSimpleLenghtQuery;

#endif