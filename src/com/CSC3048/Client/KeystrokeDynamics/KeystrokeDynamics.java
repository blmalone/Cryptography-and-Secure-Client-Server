package com.CSC3048.Client.KeystrokeDynamics;

import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.util.ArrayList;

public class KeystrokeDynamics implements KeyListener{

    //Store the key PATTERN but not the actual keys pressed. This means we can compare the patterns
    //Time between presses

    private long timeLastEventFinished = 0;
    private ArrayList<Long> allEvents = new ArrayList<>();

    @Override
    public void keyTyped(KeyEvent e) {
        if(timeLastEventFinished == 0) {
            //This is the first letter press
            timeLastEventFinished = System.nanoTime();
            return;
        }

        long currentTime = System.nanoTime();
        long timeElapsed = currentTime - timeLastEventFinished;
        allEvents.add(timeElapsed);
        timeLastEventFinished = System.nanoTime();
    }

    public ArrayList<Long> GetAllEvents() {
        return allEvents;
    }

    @Override
    public void keyPressed(KeyEvent e) {
    }

    @Override
    public void keyReleased(KeyEvent e) {
    }

    public void reset() {
        allEvents = new ArrayList<>();
        timeLastEventFinished = 0;
    }
}
