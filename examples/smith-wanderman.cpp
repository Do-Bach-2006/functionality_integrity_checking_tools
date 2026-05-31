#include <algorithm>
#include <iostream>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <string>
#include <vector>

namespace py = pybind11;

// Cấu trúc đại diện cho 1 API Call được truyền từ Python
struct ApiCall {
  std::string name;
  std::string
      attributes;   // Dump các arguments thành 1 chuỗi string để dễ so sánh
  bool is_critical; // Đánh dấu các API nhạy cảm (VD: VirtualAllocEx,
                    // CreateRemoteThread)
};

// Hàm tính điểm (Similarity Scoring) theo công thức của nghiên cứu
double calculate_pair_score(const ApiCall &a, const ApiCall &b) {
  // Trọng số cấu hình
  double wt = 3.0;   // API Name Match
  double nwt = -2.0; // API Name Mismatch
  double wa = 2.0;   // API Attribute Match
  double nwa = -2.0; // API Attribute Mismatch
  double wb = 20.0;  // Bias Multiplier cho Critical API

  double name_score = (a.name == b.name) ? wt : nwt;
  
  double attr_score = 0.0;
  if (!a.attributes.empty() && !b.attributes.empty()) {
    attr_score = (a.attributes == b.attributes) ? wa : nwa;
  }

  // Bias: Nếu một trong hai là API nguy hiểm, áp dụng hệ số nhân để neo
  // (anchor) alignment
  double bias = (a.is_critical || b.is_critical) ? wb : 1.0;

  return bias * (name_score + attr_score);
}

// Cấu trúc lưu trữ khối Match Block để phục vụ cho thuật toán Difference
// Pruning (td = 0.02)
struct MatchBlock {
  int start_idx;
  int end_idx;
  int length;
  int gap_before;
  int gap_after;
};

// Thuật toán Smith-Waterman Local Alignment với Affine Gap Penalty
double calculate_similarity(const std::vector<ApiCall> &seq1,
                            const std::vector<ApiCall> &seq2) {
  int n = seq1.size(); // Original Sequence
  int m = seq2.size(); // Adversarial Sequence

  if (n == 0 || m == 0)
    return 0.0;

  // Phase 4.1: Tính Theoretical Maximum Score
  // Điểm tuyệt đối tối đa đạt được nếu file gốc được căn chỉnh hoàn hảo với
  // chính nó
  double theoretical_max_score = 0.0;
  for (const auto &api : seq1) {
    theoretical_max_score += calculate_pair_score(api, api);
  }

  if (theoretical_max_score <= 0.0)
    return 0.0; // Safeguard

  // Phase 3: Khởi tạo các ma trận Quy hoạch động (Dynamic Programming)
  // H: Điểm local alignment lớn nhất
  // E: Trạng thái đi ngang (Insertion/Gap trên Original)
  // F: Trạng thái đi dọc (Deletion/Gap trên ADV)
  std::vector<std::vector<double>> H(n + 1, std::vector<double>(m + 1, 0.0));
  std::vector<std::vector<double>> E(n + 1, std::vector<double>(m + 1, 0.0));
  std::vector<std::vector<double>> F(n + 1, std::vector<double>(m + 1, 0.0));

  // Ma trận lưu vết (Traceback): 0=STOP, 1=DIAG(Match), 2=UP(F), 3=LEFT(E)
  std::vector<std::vector<int>> tb(n + 1, std::vector<int>(m + 1, 0));

  double ga = -2.0;  // Gap Opening Penalty
  double gb = -0.10; // Gap Extension Penalty

  double max_score = 0.0;
  int max_i = 0, max_j = 0;

  // Điền ma trận DP
  for (int i = 1; i <= n; ++i) {
    for (int j = 1; j <= m; ++j) {
      double score_match = calculate_pair_score(seq1[i - 1], seq2[j - 1]);

      // Tính toán Affine Gaps
      E[i][j] = std::max(H[i][j - 1] + ga, E[i][j - 1] + gb);
      F[i][j] = std::max(H[i - 1][j] + ga, F[i - 1][j] + gb);

      // Match/Mismatch từ ô chéo
      double diag = H[i - 1][j - 1] + score_match;

      H[i][j] = std::max({0.0, diag, E[i][j], F[i][j]});

      // Cập nhật hướng Traceback
      if (H[i][j] == 0.0) {
        tb[i][j] = 0;
      } else if (H[i][j] == diag) {
        tb[i][j] = 1;
      } else if (H[i][j] == F[i][j]) {
        tb[i][j] = 2;
      } else {
        tb[i][j] = 3;
      }

      // Ghi nhận điểm max cục bộ để bắt đầu traceback
      if (H[i][j] > max_score) {
        max_score = H[i][j];
        max_i = i;
        max_j = j;
      }
    }
  }

  // Thực hiện Traceback để lấy danh sách các cặp API được align
  std::vector<std::pair<int, int>> aligned_pairs;
  int curr_i = max_i;
  int curr_j = max_j;

  while (curr_i > 0 && curr_j > 0 && H[curr_i][curr_j] > 0) {
    if (tb[curr_i][curr_j] == 1) {
      aligned_pairs.push_back({curr_i - 1, curr_j - 1});
      curr_i--;
      curr_j--;
    } else if (tb[curr_i][curr_j] == 2) {
      curr_i--; // Bỏ qua 1 API bên Original
    } else if (tb[curr_i][curr_j] == 3) {
      curr_j--; // Bỏ qua 1 API bên ADV
    } else {
      break;
    }
  }

  // Do Traceback đi ngược từ dưới lên, cần đảo ngược mảng lại
  std::reverse(aligned_pairs.begin(), aligned_pairs.end());

  // Phase 3.2: Thực hiện Difference Pruning (td = 0.02)
  // Loại bỏ các matches siêu nhỏ lọt thỏm giữa 2 đoạn evasion injection khổng
  // lồ
  double td = 0.02;
  double final_absolute_score = 0.0;

  if (!aligned_pairs.empty()) {
    std::vector<MatchBlock> blocks;
    MatchBlock current_block = {0, 0, 1, 0, 0};

    // Nhóm các cặp align liên tiếp thành các Block
    for (size_t k = 1; k < aligned_pairs.size(); ++k) {
      int gap_seq1 = aligned_pairs[k].first - aligned_pairs[k - 1].first - 1;
      int gap_seq2 = aligned_pairs[k].second - aligned_pairs[k - 1].second - 1;

      if (gap_seq1 == 0 && gap_seq2 == 0) {
        current_block.length++;
        current_block.end_idx = k;
      } else {
        current_block.gap_after = gap_seq1 + gap_seq2;
        blocks.push_back(current_block);

        current_block.start_idx = k;
        current_block.end_idx = k;
        current_block.length = 1;
        current_block.gap_before = gap_seq1 + gap_seq2;
        current_block.gap_after = 0;
      }
    }
    blocks.push_back(current_block); // Đẩy block cuối cùng

    // Duyệt qua từng Block để tính điểm, Prune nếu không đạt tỉ lệ td
    for (const auto &block : blocks) {
      double surrounding_gaps = block.gap_before + block.gap_after;

      // Pruning: Nếu độ dài match < 2% tổng số gap bao quanh nó -> vứt bỏ (xem
      // như noise)
      if (surrounding_gaps > 0 &&
          (double)block.length < (td * surrounding_gaps)) {
        continue; // Bỏ qua, không cộng điểm cho block này
      }

      // Nếu sống sót qua Pruning, cộng dồn điểm của các cặp vào final score
      for (int k = block.start_idx; k <= block.end_idx; ++k) {
        final_absolute_score += calculate_pair_score(
            seq1[aligned_pairs[k].first], seq2[aligned_pairs[k].second]);
      }
    }
  }

  // Phase 4.2: Chuẩn hóa về phần trăm (0 - 100%)
  double similarity_percentage =
      (final_absolute_score / theoretical_max_score) * 100.0;

  // Clamp giới hạn
  if (similarity_percentage < 0.0)
    similarity_percentage = 0.0;
  if (similarity_percentage > 100.0)
    similarity_percentage = 100.0;

  return similarity_percentage;
}

// ==========================================
// CẤU HÌNH PYBIND11 BINDING MODULE
// ==========================================
PYBIND11_MODULE(fast_sw, m) {
  m.doc() = "C++ Smith-Waterman Affine Gap module for RL Malware Evasion";

  py::class_<ApiCall>(m, "ApiCall")
      .def(py::init<std::string, std::string, bool>())
      .def_readwrite("name", &ApiCall::name)
      .def_readwrite("attributes", &ApiCall::attributes)
      .def_readwrite("is_critical", &ApiCall::is_critical)
      .def("__repr__",
           [](const ApiCall &a) { return "<ApiCall name='" + a.name + "'>"; });

  m.def("calculate_similarity", &calculate_similarity,
        "Calculate % similarity between Original and ADV API sequences",
        py::arg("seq1"), py::arg("seq2"));
}