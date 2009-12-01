/*
Copyright (C) 2007 - 2009  fhscan project.
Andres Tarasco - http://www.tarasco.org/security

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

#ifndef _TREE__H_
#define _TREE__H_

class TreeNode 
{

	char		   *text;
	int				count;
	class TreeNode *left;
	class TreeNode *right;
	class TreeNode *ParentItem;

	class bTree	   *ParentTree;
	class bTree    *ChildTree;
	void 		   *data;


public:

	TreeNode();
	TreeNode(HTTPCSTR lpTreeNodeName);
	TreeNode(HTTPCSTR lpTreeNodeName,TreeNode *Parent);
	~TreeNode();

	void SetTreeNodeName(HTTPCSTR lpTreeNodeName);
	char *GetTreeNodeName(void) { return (text); };
	
	void SetTreeNodeCount(const int n) { count=n; }
	int GetTreeNodeCount(void) { return (count); }

	void SetTreeNodeLeft(TreeNode *newleft);
	class TreeNode*	GetTreeNodeLeft(void) { return (left); }

	void SetTreeNodeRight(TreeNode *newright);
	class TreeNode*	GetTreeNodeRight(void) { return (right); }
	
	void SetTreeNodeParentItem (TreeNode *Parent) { ParentItem = Parent; }
	class TreeNode * GetTreeNodeParentItem(void) { return ParentItem; }
	class TreeNode * GetTreeNodeParentItemTop(void);

	void SetTreeNodeParentTree( class bTree *ptree) {ParentTree = ptree;}
	class bTree * GetTreeNodeParentTree(void) {return ParentTree;}

	void SetTreeNodeChildTree(bTree *SubTree) { ChildTree = SubTree; }
	class bTree *GetTreeNodeChildTree(void) { return (ChildTree); }
	
	void SetData(void *ptr) { data = ptr; }
	void *GetData(void) { return data ; }

	
	class bTree* GetNewTreeNodeSubTree(void);
	class bTree* GetNewTreeNodeSubTree(char *lpSubTree);
	class TreeNode	*GetTreeNodeItemID(int n);

};


class bTree {
private:
	char *text;
	TreeNode *root;
	int count;
public:
	bTree();
	bTree(char *lpTreeName);
	~bTree();
	void		SetTreeName(HTTPCSTR lpTreeName);
	int			GetCount() { return (count); }
	TreeNode	*TreeExistItem(HTTPCSTR lpTreeItemName);
	TreeNode	*GetTreeNodeItemID(int n);
	TreeNode	*TreeInsert(HTTPCSTR str,TreeNode *ParentItem);
	TreeNode	*TreeInsert(HTTPCSTR str);

	void SubTreePrint(TreeNode *subtree);
	void TreePrint();
};

#endif
