# 一条消息的成功响应保持一致

§3.4.4.3 允许一条消息有多个语义响应，但后续响应必须沿用首个响应的 opcode 与返回码，
或报告错误。DEFAULT 的完整含义还包括：原 Job/MID/长度/generation、RC_OK，以及
Table3-26 的 EXPECTED list。

原接收路径会在中间包返回 DEFAULT，末包改为全长 RESPONSE。现在满足所有默认字段
的成功结果保持 DEFAULT，包含消息末包。消息结果仍可设置保证交付：PDS 的 REQ_CLEAR
和响应缓存负责退休，这个交付属性与语义 opcode 独立，不需要为了 Clear 改变 opcode。

ROD 捕获 unexpected payload 时，Table3-26 要求 OVERFLOW list。这个事实存入消息状态，
即使稍后有应用投递、缓冲内容已放置，也不会丢失。OVERFLOW 不是默认字段，因此此消息
的成功结果使用 RESPONSE，并标记保证交付，防止 ACK 合并把该信息变成 EXPECTED。

`report_message_result` 描述当前调用是否报告最终/错误消息结果，而不是指定一种线编码。
编码由实际字段决定。错误仍使用 RESPONSE：第一次错误保证交付，后续同消息错误尽力
重复；NO_RESPONSE 仍只表示处理未完成，不是一个成功结果。

`receive_end_marker_test` 的16种报文情形直接观察源 PDS 交给 SES 的 opcode/list，
检查 EXPECTED/DEFAULT 与 OVERFLOW/RESPONSE 在同消息内一致，并从实际线上检查
REQ_CLEAR、完成次数与最终状态退休。基线的48 B WRITE 实际从opcode0切换到1，失败日志
保留。`guaranteed_error_test`、tagged/迟投递、公开 READ/原子/源匹配与双provider进程
另检查错误保证和共同路径回归。实际结果以生成验证报告为准。
