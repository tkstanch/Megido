/**
 * Webpack Configuration for NoSQLAttackerGUI Component
 * Compiles TypeScript React component to production-ready JavaScript
 */

const path = require('path');

module.exports = {
  mode: 'production', // Use 'development' for debugging
  entry: './sqli_web/frontend/components/NoSQLAttackerGUI.tsx',
  output: {
    path: path.resolve(__dirname, 'static/js/dist'),
    filename: 'NoSQLAttackerGUI.bundle.js',
    library: 'NoSQLAttackerGUI',
    libraryTarget: 'umd',
    globalObject: 'this',
  },
  resolve: {
    extensions: ['.ts', '.tsx', '.js', '.jsx'],
  },
  module: {
    rules: [
      {
        test: /\.(ts|tsx)$/,
        exclude: /node_modules/,
        use: {
          loader: 'ts-loader',
          options: {
            configFile: path.resolve(__dirname, 'sqli_web/frontend/tsconfig.json'),
          },
        },
      },
      {
        test: /\.css$/,
        use: ['style-loader', 'css-loader', 'postcss-loader'],
      },
    ],
  },
  externals: {
    react: {
      root: 'React',
      commonjs2: 'react',
      commonjs: 'react',
      amd: 'react',
    },
    'react-dom': {
      root: 'ReactDOM',
      commonjs2: 'react-dom',
      commonjs: 'react-dom',
      amd: 'react-dom',
    },
  },
  devtool: 'source-map',
  optimization: {
    minimize: true,
  },
};
