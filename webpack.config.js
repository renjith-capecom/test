const path = require('path');

module.exports = {
  mode: 'development',
  target: 'node',
  entry: './src/server.js',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'server.js',
    libraryTarget: 'commonjs2'
  },
  externals: {
    // Keep react packages as external - we need them unbundled for server conditions
    'react': 'commonjs react',
    'react-dom': 'commonjs react-dom',
    'react-server-dom-webpack/server': 'commonjs react-server-dom-webpack/server',
    'react-server-dom-webpack/client': 'commonjs react-server-dom-webpack/client'
  },
  resolve: {
    extensions: ['.js', '.jsx']
  }
};
