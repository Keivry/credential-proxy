# truncated-stream-safe-terminal

截断流终止事件安全化：已 complete 静默丢弃残留 buf；未 complete 的文本/工具调用截断不再伪造成功终止，让下游走 stub/重试保护
