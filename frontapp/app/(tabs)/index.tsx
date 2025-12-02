import { View, StyleSheet } from 'react-native';
import WebViewComponent from '../../components/webview';

export default function HomeScreen() {
  return (
    <View style={styles.container}>
      <WebViewComponent 
        initialUrl="https://kmj.shscript.com/" 
        showControls={true} 
      />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
});