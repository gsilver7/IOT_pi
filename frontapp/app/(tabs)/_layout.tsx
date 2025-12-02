import { Tabs } from 'expo-router';
import React from 'react';
import { Ionicons } from '@expo/vector-icons';

import { HapticTab } from '@/components/haptic-tab';
import { Colors } from '@/constants/theme';
import { useColorScheme } from '@/hooks/use-color-scheme';

export default function TabLayout() {
  const colorScheme = useColorScheme();

  return (
    <Tabs
      screenOptions={{
        tabBarActiveTintColor: Colors[colorScheme ?? 'light'].tint,
        headerShown: false,
        tabBarButton: HapticTab,
        // tabBarStyle: { display: 'none' }, // 이 줄 삭제 또는 주석처리
      }}>
      
      {/* 첫 번째 탭: 웹뷰 */}
      <Tabs.Screen 
        name="index" 
        options={{
          title: '홈',
          tabBarIcon: ({ color, focused }) => (
            <Ionicons 
              name={focused ? 'home' : 'home-outline'} 
              size={24} 
              color={color} 
            />
          ),
        }}
      />

      {/* 두 번째 탭: 블루투스 */}
      <Tabs.Screen 
        name="bluetooth" 
        options={{
          title: '블루투스',
          tabBarIcon: ({ color, focused }) => (
            <Ionicons 
              name={focused ? 'bluetooth' : 'bluetooth-outline'} 
              size={24} 
              color={color} 
            />
          ),
        }}
      />
      
    </Tabs>
  );
}