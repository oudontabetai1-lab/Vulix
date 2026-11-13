/* スキャン履歴の表示ラベル（ポータル / 統合画面の履歴で共有）。

   生の API 値（done / scanning 等）をそのまま見せず、日本語の状態名と
   「途中」件数の注記に揃える。 */
(function (global) {
  'use strict';

  const STATUS_LABELS = {
    done: '完了',
    scanning: '実行中',
    aborted: '中断',
    error: 'エラー',
    incomplete: '未完了',
    interrupted: '中断（途中）',
  };
  const statusLabel = (value) => STATUS_LABELS[String(value || '').toLowerCase()] || (value || '不明');
  // 途中経過の件数に添える注記（partial でなければ空文字）。
  const countsNote = (partial, running) => {
    if (!partial) return '';
    return running ? '件（実行中・途中）' : '件（途中）';
  };

  global.VulixHistoryLabels = { STATUS_LABELS, statusLabel, countsNote };
})(typeof globalThis !== 'undefined' ? globalThis : window);