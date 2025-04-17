package consistencyhash

import (
	"crypto/md5"
	"sort"
	"strconv"
	"sync"
)

type ConsistentHash struct {
	replicas int             // 虚拟节点倍数
	keys     []int           // 哈希环
	hashMap  map[int]string  // 虚拟节点到真实节点的映射
	nodes    map[string]bool // 真实节点集合
	mu       sync.RWMutex    // 读写锁
}

// NewConsistentHash 创建一个新的ConsistentHash实例
func NewConsistentHash(replicas int) *ConsistentHash {
	return &ConsistentHash{
		replicas: replicas,
		hashMap:  make(map[int]string),
		nodes:    make(map[string]bool),
	}
}

// AddNode 添加节点到哈希环
func (c *ConsistentHash) AddNode(node string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.nodes[node]; ok {
		return // 节点已存在
	}

	c.nodes[node] = true

	// 为每个真实节点创建replicas个虚拟节点
	for i := 0; i < c.replicas; i++ {
		virtualNode := node + "#" + strconv.Itoa(i)
		hash := int(c.hash(virtualNode))
		c.keys = append(c.keys, hash)
		c.hashMap[hash] = node
	}

	// 重新排序哈希环
	sort.Ints(c.keys)
}

// RemoveNode 从哈希环中移除节点
func (c *ConsistentHash) RemoveNode(node string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.nodes[node]; !ok {
		return // 节点不存在
	}

	delete(c.nodes, node)

	// 移除所有虚拟节点
	for i := 0; i < c.replicas; i++ {
		virtualNode := node + "#" + strconv.Itoa(i)
		hash := int(c.hash(virtualNode))

		// 从keys中删除
		index := sort.SearchInts(c.keys, hash)
		if index < len(c.keys) && c.keys[index] == hash {
			c.keys = append(c.keys[:index], c.keys[index+1:]...)
		}

		// 从hashMap中删除
		delete(c.hashMap, hash)
	}
}

// GetNode 获取key对应的节点
func (c *ConsistentHash) GetNode(key string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.keys) == 0 {
		return ""
	}

	hash := int(c.hash(key))

	// 使用二分查找找到第一个大于等于hash的节点
	idx := sort.Search(len(c.keys), func(i int) bool {
		return c.keys[i] >= hash
	})

	// 如果没找到大于等于的节点，则使用第一个节点（环形结构）
	if idx == len(c.keys) {
		idx = 0
	}

	return c.hashMap[c.keys[idx]]
}

// hash 计算字符串的哈希值（使用MD5）
func (c *ConsistentHash) hash(key string) uint32 {
	h := md5.New()
	h.Write([]byte(key))
	hash := h.Sum(nil)
	return uint32(hash[0])<<24 | uint32(hash[1])<<16 | uint32(hash[2])<<8 | uint32(hash[3])
}
