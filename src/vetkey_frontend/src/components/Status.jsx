/**
 * 状态显示组件
 */

import React from 'react';

function Status({ status }) {
  return (
    <div className="status-section">
      <h3>状态</h3>
      <pre className="status-text">{status || '准备就绪'}</pre>
    </div>
  );
}

export default Status; 