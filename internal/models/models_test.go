package models

import (
	"testing"
)

func TestFlameNode_GetChild(t *testing.T) {
	root := &FlameNode{Name: "root"}

	// Get new child
	child1 := root.GetChild("func1")
	if child1 == nil || child1.Name != "func1" {
		t.Error("GetChild should create new child")
	}
	if len(root.Children) != 1 {
		t.Errorf("root.Children = %d, want 1", len(root.Children))
	}

	// Get same child again
	child1Again := root.GetChild("func1")
	if child1Again != child1 {
		t.Error("GetChild should return existing child")
	}
	if len(root.Children) != 1 {
		t.Error("GetChild should not duplicate children")
	}

	// Get different child
	child2 := root.GetChild("func2")
	if child2 == nil || child2.Name != "func2" {
		t.Error("GetChild should create second child")
	}
	if len(root.Children) != 2 {
		t.Errorf("root.Children = %d, want 2", len(root.Children))
	}
}

func TestFlameDiffNode_GetChild(t *testing.T) {
	root := &FlameDiffNode{Name: "root"}

	child := root.GetChild("diff_func")
	if child == nil || child.Name != "diff_func" {
		t.Error("GetChild should create new child")
	}

	// Verify it returns existing
	same := root.GetChild("diff_func")
	if same != child {
		t.Error("GetChild should return same child")
	}
}
