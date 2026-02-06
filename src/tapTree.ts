export type TapLeaf = {
  miniscript: string;
};

export type TapBranch = {
  left: TapTreeNode;
  right: TapTreeNode;
};

export type TapTreeNode = TapLeaf | TapBranch;
