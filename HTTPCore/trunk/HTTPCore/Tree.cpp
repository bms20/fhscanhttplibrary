/*
 Copyright (C) 2007 - 2012  fhscan project.
 Andres Tarasco - http://www.tarasco.org/security - http://www.tarlogic.com

 All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:
 1. Redistributions of source code must retain the above copyright
 notice, this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
 notice, this list of conditions and the following disclaimer in the
 documentation and/or other materials provided with the distribution.
 3. All advertising materials mentioning features or use of this software
 must display the following acknowledgement:
 This product includes software developed by Andres Tarasco fhscan
 project and its contributors.
 4. Neither the name of the project nor the names of its contributors
 may be used to endorse or promote products derived from this software
 without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 SUCH DAMAGE.
 */
#include "Build.h"
#include "Tree.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//-----------------------------------------------------------------------------
TreeNode::TreeNode() {
	TreeNode(NULL, NULL);
}

//-----------------------------------------------------------------------------

TreeNode::TreeNode(HTTPCSTR lpTreeNodeName) {
	TreeNode(lpTreeNodeName, NULL);
}
//-----------------------------------------------------------------------------

TreeNode::TreeNode(HTTPCSTR lpTreeNodeName, TreeNode *Parent) {
	text = NULL;
	count = 0;
	left = NULL;
	right = NULL;
	ParentItem = NULL;

	ParentTree = NULL;
	ChildTree = NULL;
	data = NULL;
	if (lpTreeNodeName)
		SetTreeNodeName(lpTreeNodeName);
	if (Parent)
		SetTreeNodeParentItem(Parent);
}

//-----------------------------------------------------------------------------
TreeNode::~TreeNode() {
	count = 0;
	if (left) {
		delete(left);
		left = NULL;
	}
	if (right) {
		delete(right);
		right = NULL;
	}
	if (text) {
		free(text);
		text = NULL;
	}
	ParentItem = NULL;
	ParentTree = NULL;

	if (ChildTree) {
		delete ChildTree;
		ChildTree = NULL;
	}
	data = NULL;
}

//-----------------------------------------------------------------------------
void TreeNode::SetTreeNodeName(HTTPCSTR lpTreeNodeName) {
	if (text)
		free(text);
	if (lpTreeNodeName) {
		text = _tcsdup(lpTreeNodeName);
	}
	else {
		text = NULL;
	}
}

//-----------------------------------------------------------------------------
void TreeNode::SetTreeNodeRight(TreeNode *newright) {
	right = newright;

	TreeNode *parent = this;

	do {
		parent->count++;
		parent = parent->ParentItem;

	}
	while (parent);

}

//-----------------------------------------------------------------------------
 void TreeNode::SetTreeNodeLeft(TreeNode *newleft) {

 left = newleft;

 TreeNode *parent = this;
 do
 {
 parent->count++;
 parent = parent->ParentItem;

 } while (parent);
 }
//-----------------------------------------------------------------------------
class TreeNode* TreeNode::GetTreeNodeItemID(int n) {
	return (ParentTree->GetTreeNodeItemID(n));
}

//-----------------------------------------------------------------------------
class bTree* TreeNode::GetNewTreeNodeSubTree() {
	ChildTree = new bTree;
	return (ChildTree);
}

//-----------------------------------------------------------------------------
class bTree* TreeNode::GetNewTreeNodeSubTree(HTTPCHAR * lpSubTree) {
	ChildTree = new bTree(lpSubTree);
	return (ChildTree);
}

class TreeNode* TreeNode::GetTreeNodeParentItemTop(void) {
	TreeNode* top = this->GetTreeNodeParentItem();
	while (top->GetTreeNodeParentItem()) {
		top = top->GetTreeNodeParentItem();
	}
	return (top);
}

//-----------------------------------------------------------------------------
bTree::bTree() {
	text = NULL;
	root = NULL;
	count = 0;
}

//-----------------------------------------------------------------------------
 bTree::bTree(HTTPCCHAR *lpTreeName)
 {
 if (lpTreeName)
 {
 text= _tcsdup(lpTreeName);
 } else {
 text = NULL;
 }
 root = NULL;
 count = 0;
 }
//-----------------------------------------------------------------------------
void bTree::SetTreeName(HTTPCSTR lpTreeName) {
	if (text) {
		free(text);
		text = NULL;
	}
	if (lpTreeName) {
		text = _tcsdup(lpTreeName);
	}
}
//-----------------------------------------------------------------------------
 bTree::~bTree()
 {
 if (text)
 {
 free(text);
 text = NULL;
 }
 if (root) {
 delete root;
 root = NULL;
 }
 count = 0;
 }


//-----------------------------------------------------------------------------

TreeNode *bTree::TreeExistItem(HTTPCSTR lpTreeItemName) {
	TreeNode *x;
	if (root == NULL) {
		return (NULL);
	}
	/* search the tree */
	x = root;
	while (x != NULL) {
		int ret = _tcscmp(x->GetTreeNodeName(), lpTreeItemName);

		if (ret == 0) {
			return (x);
		}
		else {
			if (ret < 0) {
				x = x->GetTreeNodeLeft();
			}
			else {
				x = x->GetTreeNodeRight();
			}
		}
	}

	return (NULL);
}

//-----------------------------------------------------------------------------
/*
 Returns a TreeNode element from the tree.
 Elements are returned from the tree as if they come from a linear and sorted array.
 */

TreeNode *bTree::GetTreeNodeItemID(int value) {
	int n = value + 1; /* Cheat to allow the counter to be 0 */
	if ((count < n) || (n <= 0)) {
		return (NULL);
	}
	TreeNode *node = root;
	int total = 0;
#define NLEFT node->GetTreeNodeLeft()->GetTreeNodeCount() +1
#define NRIGHT node->GetTreeNodeRight()->GetTreeNodeCount() +1
	while ((node != NULL) && (total < n)) {
		if (node->GetTreeNodeLeft()) {
			if (NLEFT + total >= n) {
				node = node->GetTreeNodeLeft();
			}
			else {
				total += NLEFT; // add nodes from left side
				total++; // Add current node
				if (total == n) {
					return (node);
				}
				else {
					node = node->GetTreeNodeRight();
				}

			}
		}
		else if (node->GetTreeNodeRight()) {
			total++;
			if (total == n) {
				return (node);
			}
			else {
				node = node->GetTreeNodeRight();
			}
		}
		else {
			total++;
			if (total == n) {
				return (node);
			}
			else {
				/* FATAL - ##CRITICAL UNEXPECTED ERROR##: BAD IMPLEMENTATION? */
				return (NULL);
			}
		}
	}
	return (NULL);
}
//-----------------------------------------------------------------------------

/* Insert a text value into the tree - if the value doesn´t already exists, increment
 the count for parent nodes. */

TreeNode* bTree::TreeInsert(HTTPCSTR str) {
	return (TreeInsert(str, NULL));
}
//-----------------------------------------------------------------------------
 TreeNode* bTree::TreeInsert(HTTPCSTR str,TreeNode *ParentItem)
 {
 if (ParentItem == NULL)
 {
 if (root==NULL)
 {
 TreeNode *newnode = new TreeNode(str,NULL);
 newnode->SetTreeNodeParentTree(this);
 root = newnode;
 count++;
 return ( root);
 } else
 {
 TreeNode *y=NULL;
 TreeNode *x=root;

 while (x != NULL) {
 if (_tcscmp(x->GetTreeNodeName(), str)==0)
 {
/* already Exists */
return (x);
} y = x;
if (_tcscmp(str, x->GetTreeNodeName()) < 0)
x = x->GetTreeNodeLeft();
else
x = x->GetTreeNodeRight();
}
/* str doesn't yet exist in tree - add it in */

TreeNode *newnode = new TreeNode(str, y);
newnode->SetTreeNodeParentTree(this);
if (_tcscmp(str, y->GetTreeNodeName()) < 0) {
y->SetTreeNodeLeft(newnode);
}
else {
y->SetTreeNodeRight(newnode);
}
this->count++; /* Add an additional element to the tree counter */
return (newnode);
}}
else {
TreeNode*newnode = ParentItem->GetTreeNodeChildTree()->TreeInsert(str, NULL);
return (newnode);
}
}

//-----------------------------------------------------------------------------
/* Print the entire tree in sorted order */

void bTree::SubTreePrint(TreeNode *subtree) {
if (subtree != NULL) {
SubTreePrint(subtree->GetTreeNodeLeft());
_tprintf(_T("%s: %d\n"), subtree->GetTreeNodeName(),
	subtree->GetTreeNodeCount());
SubTreePrint(subtree->GetTreeNodeRight());
}
}

void bTree::TreePrint() {
SubTreePrint(root);
}

#if 0

//-----------------------------------------------------------------------------
// Insert a Full path of Items and creates all new nodes
TreeNode *TreeInsertItems(Tree *tree, TreeNode *parent, HTTPCHAR *strpath) {

TreeNode *node;
HTTPCHAR *str = _tcsdup(strpath);
int IsFolder = (str[strlen(str) - 1] == '/');
HTTPCHAR *path = _tcstok(str, "/");

if (!path) {
node = TreeInsert(tree, parent, "");
}
else {
TreeNode *currentparent = parent;
Tree *base = tree;
do {
node = TreeInsert(base, currentparent, path);
path = _tcstok(NULL, "/");
if ((path) || (IsFolder)) {
if (!node->SubItems) {
node->SubItems = TreeInitialize("/");
}
currentparent = node;
base = node->SubItems;
}
else {
break;
}
}
while (path != NULL);
}
free(str);
return (node);
}

int SubTreeToArray(HTTPCHAR **array, TreeNode *subtree, int pos, int n) {
HTTPCHAR line[MXLINELEN];
int added = 0;

if (subtree != NULL) {
added = SubTreeToArray(array, subtree->left, pos, n);
if (subtree->count >= n) {
sprintf(line, "%s (%d)", subtree->text, subtree->count);
array[pos + added] = _tcsdup(line);
added++;
}
added += SubTreeToArray(array, subtree->right, pos + added, n);
}
return added;
}

/* Create a linear array of pointers to char which point to each of the
 text items in the tree which have a count of 'n' or greater.
 It is the responsibility of the calling application to free the allocated
 memory. */

HTTPCHAR** TreeToArray(Tree *tree, int n) {
HTTPCHAR **array;
int size;

size = TreeCount(tree->root, n);
array = (HTTPCHAR * *)malloc(sizeof(HTTPCHAR*)*(size + 1));
if (array) {
SubTreeToArray(array, tree->root, 0, n);
array[size] = NULL;
}
return array;
}
#endif
