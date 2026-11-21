package storage

import (
	"encoding/xml"
	"io"
	"strings"
)

// Node is a parsed XML element, for vendors (QNAP) whose CGI answers are loosely shaped XML.
type Node struct {
	Name     string
	Text     string
	Children []*Node
}

// ParseXML reads an XML document into a tree.
func ParseXML(r io.Reader) (*Node, error) {
	dec := xml.NewDecoder(r)
	dec.Strict = false
	dec.CharsetReader = func(_ string, in io.Reader) (io.Reader, error) { return in, nil }
	root := &Node{}
	stack := []*Node{root}
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			n := &Node{Name: t.Name.Local}
			top := stack[len(stack)-1]
			top.Children = append(top.Children, n)
			stack = append(stack, n)
		case xml.EndElement:
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			top := stack[len(stack)-1]
			top.Text += string(t)
		}
	}
	if len(root.Children) == 1 {
		return root.Children[0], nil
	}
	return root, nil
}

// Get follows a path of child names ("func/ownContent/root") and returns the first match.
func (n *Node) Get(path string) *Node {
	if n == nil {
		return nil
	}
	cur := n
	for _, p := range strings.Split(path, "/") {
		var next *Node
		for _, c := range cur.Children {
			if c.Name == p {
				next = c
				break
			}
		}
		if next == nil {
			return nil
		}
		cur = next
	}
	return cur
}

// All returns every child with a name.
func (n *Node) All(name string) []*Node {
	if n == nil {
		return nil
	}
	var out []*Node
	for _, c := range n.Children {
		if c.Name == name {
			out = append(out, c)
		}
	}
	return out
}

// S returns the trimmed text at a path, or "".
func (n *Node) S(path string) string {
	if c := n.Get(path); c != nil {
		return strings.TrimSpace(c.Text)
	}
	return ""
}
