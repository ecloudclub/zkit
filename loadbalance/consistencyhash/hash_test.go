package consistencyhash

import (
	"strconv"
	"testing"
)

func TestConsistentHash(t *testing.T) {
	// 创建一个一致性哈希实例，每个真实节点对应3个虚拟节点
	ch := NewConsistentHash(3)

	// 初始节点
	nodes := []string{"Node1", "Node2", "Node3"}
	for _, node := range nodes {
		ch.AddNode(node)
	}

	// 测试数据分布
	testKeys := []string{"key1", "key2", "key3", "key4", "key5", "key6"}
	initialMapping := make(map[string]string)
	for _, key := range testKeys {
		node := ch.GetNode(key)
		initialMapping[key] = node
		t.Logf("Key %s initially assigned to %s", key, node)
	}

	// 测试添加节点后的影响
	t.Run("AddNode", func(t *testing.T) {
		newNode := "Node4"
		ch.AddNode(newNode)

		movedKeys := 0
		for _, key := range testKeys {
			newNode := ch.GetNode(key)
			oldNode := initialMapping[key]
			if newNode != oldNode {
				movedKeys++
				t.Logf("Key %s moved from %s to %s", key, oldNode, newNode)
			}
		}

		// 验证只有部分key被重新分配
		if movedKeys == 0 || movedKeys == len(testKeys) {
			t.Errorf("Expected some keys to be remapped, got %d moved keys", movedKeys)
		}
	})

	// 测试移除节点后的影响
	t.Run("RemoveNode", func(t *testing.T) {
		removeNode := "Node2"
		ch.RemoveNode(removeNode)

		movedKeys := 0
		for _, key := range testKeys {
			newNode := ch.GetNode(key)
			oldNode := initialMapping[key]
			if newNode != oldNode {
				movedKeys++
				t.Logf("Key %s moved from %s to %s", key, oldNode, newNode)
			}
		}

		// 验证只有部分key被重新分配
		if movedKeys == 0 || movedKeys == len(testKeys) {
			t.Errorf("Expected some keys to be remapped, got %d moved keys", movedKeys)
		}

		// 验证被移除的节点不再被使用
		for _, key := range testKeys {
			if ch.GetNode(key) == removeNode {
				t.Errorf("Key %s still assigned to removed node %s", key, removeNode)
			}
		}
	})
}

func TestEmptyRing(t *testing.T) {
	ch := NewConsistentHash(3)
	if node := ch.GetNode("anykey"); node != "" {
		t.Errorf("Expected empty node for empty ring, got %s", node)
	}
}

func TestSingleNode(t *testing.T) {
	ch := NewConsistentHash(3)
	ch.AddNode("SingleNode")

	for i := 0; i < 10; i++ {
		key := "key" + strconv.Itoa(i)
		if node := ch.GetNode(key); node != "SingleNode" {
			t.Errorf("Expected all keys to go to SingleNode, got %s", node)
		}
	}
}
