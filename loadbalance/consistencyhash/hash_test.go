package consistencyhash

import (
	"fmt"
	"testing"
)

func TestConsistencyHash(t *testing.T) {
	// 创建一个一致性哈希实例，每个真实节点对应3个虚拟节点
	ch := NewConsistentHash(3)

	// 添加节点
	ch.AddNode("Node1")
	ch.AddNode("Node2")
	ch.AddNode("Node3")

	// 测试数据分布
	testKeys := []string{"key1", "key2", "key3", "key4", "key5", "key6"}
	for _, key := range testKeys {
		fmt.Printf("Key %s is assigned to %s\n", key, ch.GetNode(key))
	}

	// 添加一个新节点
	fmt.Println("\nAdding Node4...")
	ch.AddNode("Node4")

	// 再次测试数据分布
	for _, key := range testKeys {
		fmt.Printf("Key %s is now assigned to %s\n", key, ch.GetNode(key))
	}

	// 移除一个节点
	fmt.Println("\nRemoving Node2...")
	ch.RemoveNode("Node2")

	// 再次测试数据分布
	for _, key := range testKeys {
		fmt.Printf("Key %s is now assigned to %s\n", key, ch.GetNode(key))
	}
}
