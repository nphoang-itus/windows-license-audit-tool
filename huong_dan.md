# Hướng dẫn kiểm tra bản quyền Windows/Office

Tài liệu này dành cho người dùng không chuyên kỹ thuật.

## 1. Mở PowerShell

1. Mở thư mục chứa công cụ.
2. Bấm chuột phải vào vùng trống trong thư mục.
3. Chọn **Open in Terminal** hoặc **Open PowerShell window here**.

Nếu đang ở ổ `Z:`, có thể thấy dòng giống như:

```powershell
PS Z:\>
```

## 2. Chạy kiểm tra cơ bản

Chạy lệnh sau:

```powershell
powershell.exe -ExecutionPolicy Bypass -NoProfile -File .\run-audit.ps1
```

Sau khi chạy xong, công cụ sẽ:

- Tạo báo cáo JSON.
- Tạo báo cáo HTML.
- Tự mở file HTML bằng trình duyệt.

## 3. Chạy kiểm tra có quét dấu hiệu nghi vấn

Nếu muốn kiểm tra thêm tên app, process, service, scheduled task và một số tên
file nghi vấn, chạy:

```powershell
powershell.exe -ExecutionPolicy Bypass -NoProfile -File .\run-audit.ps1 -IncludeSuspiciousScan
```

Lưu ý: chế độ này vẫn chỉ đọc dữ liệu, không xóa hoặc sửa gì trên máy.

## 4. Xuất báo cáo ra thư mục khác

Ví dụ xuất ra `C:\Temp\AuditReports`:

```powershell
powershell.exe -ExecutionPolicy Bypass -NoProfile -File .\run-audit.ps1 -OutputDir C:\Temp\AuditReports
```

## 5. Không muốn tự mở trình duyệt

Nếu chỉ muốn tạo file báo cáo, không mở browser:

```powershell
powershell.exe -ExecutionPolicy Bypass -NoProfile -File .\run-audit.ps1 -NoOpen
```

## 6. Xem kết quả ở đâu?

Mặc định báo cáo nằm trong thư mục:

```text
exports
```

Bạn sẽ thấy 2 file:

- `windows-license-audit-....html`: mở bằng trình duyệt, dễ đọc.
- `windows-license-audit-....json`: dữ liệu thô cho kỹ thuật.

## 7. Công cụ này có an toàn không?

Công cụ chỉ đọc thông tin để lập báo cáo. Công cụ không kích hoạt Windows,
không đổi key, không xóa file, không sửa registry và không thay đổi license.

## 8. Cách hiểu kết luận

- **Bình thường / có khả năng hợp lệ**: chưa thấy dấu hiệu bất thường rõ ràng.
- **Cần kiểm tra thủ công**: cần người quản trị hoặc IT đối chiếu thêm.
- **Có dấu hiệu nghi vấn**: có dữ liệu cần xem lại, chưa phải kết luận tuyệt đối.
- **Rủi ro cao**: nên kiểm tra sớm với người phụ trách IT/license.

Kết quả kích hoạt không phải bằng chứng pháp lý tuyệt đối về quyền sở hữu
license. Nếu dùng KMS, cần đối chiếu với hệ thống và chính sách của tổ chức.
