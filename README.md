# LuminLog

#### 基于C++的通用异步日志库

使用方法：导入头文件即可，不需要任何外部依赖

代码示例：

```cpp
int main()
{
    Logger logger("log.txt");
    logger.log("启动程序 {}", "v1.0");
    logger.debug("连接成功，耗时 {}ms", 123);
    logger.warning("内存使用率已达 {}%", 87.5);
    logger.error("异常：{}", std::string("NullPointerException"));
}
