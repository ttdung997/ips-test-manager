# Quy trình cài đặt và sử dụng IPS-Manager
## Tổng quan
- Manager phiên bản demo được nhóm BKCS thiết kế dựa trên nền tảng nodeJS, với các cấu trúc tuân theo chuẩn API đã quy định trong báo cáo kèm theo
-  Đề nghị  API được thiết kế trong hệ thống IPS-Manager trong thực tế phải theo đúng các định dạng như mẫu, để quá trình tương tác với HOST-IPS diễn ra thuận tiện nhất
## Cài đặt và sử dụng IPS-Manager phiên bảo demo
- IPS-Manager phiên bảo demo được lập trình để sử dụng trên các hệ điều hành linux

### Cài đặt
```sh
curl -sL https://deb.nodesource.com/setup_12.x | sudo -E bash -
sudo apt install nodejs
```
### Chạy hệ thống

```sh
node server.js
```
Để chạy tiến trình ngầm, sử dụng lệnh:
```sh
node server.js >/dev/null 2>&1 &
```

Nhóm BKCS đã xây dựng và cài đặt mẫu trên server 112.137.130.53, cổng mặc định của chương trình là 8000