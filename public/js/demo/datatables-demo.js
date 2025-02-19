$(document).ready(function () {
  $('#dataTable').DataTable({
      pageLength: 5, // ডিফল্ট ৫ সেট করা হলো
      lengthMenu: [[5, 10, 25, 50, -1], [5, 10, 25, 50, "All"]] // ড্রপডাউন অপশন
  });
});
