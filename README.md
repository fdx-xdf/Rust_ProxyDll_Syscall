学习文章：https://0xdarkvortex.dev/proxying-dll-loads-for-hiding-etwti-stack-tracing/

参考项目：https://github.com/pard0p/CallstackSpoofingPOC

说明：在debug模式下，代码中汇编平当前函数栈的部分需要修改，或者可以自己改成global_asm的形式
项目综合了上面的学习文章和间接syscall
